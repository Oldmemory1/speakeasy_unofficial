# Speakeasy 受控 child execution 开发手册

> 状态：阶段 1 model-only 已实现；步骤 6 小批实验已执行，child execution
> 仍关闭。真实 scheduler/pipeline 接入、`mira` self-target 和 `padodor`
> 失败语义尚未通过，depth=2 未获批准。
>
> 日期：2026-11-01；当前工作包更新于 2026-11-04
>
> Speakeasy 修复前基线：`b970251` (`chore: checkpoint emulation engine before controlled child execution`)
>
> 需求与样本证据来源：`src/dynamic_stage_new/dev2.md`

## 1. 目标

受控 child execution 的目标是在**同一个 Speakeasy 仿真进程内**，为一个已经由父样本请求启动、且目标 PE 字节确实可获得的子程序建立独立的逻辑进程上下文，并只在该上下文内执行有限次数的入口点和 API。

它必须回答以下问题：

```text
父样本请求启动什么？
  -> 目标路径能否解析到可信的仿真内字节？
  -> 字节是否是完整、可执行且架构匹配的 PE？
  -> 执行策略是否允许该 child？
  -> process/thread 是否创建并进入 run queue？
  -> child 是否真正到达入口点？
  -> child 的 API、文件、注册表、网络和内存事件分别属于谁？
  -> child 是否在与 parent 相同限额、独立计数的预算内结束，终止原因是什么？
```

首个实现阶段只处理保守、可审计的场景：

- `mira` 的 self-relaunch；
- 完整 dropped executable；
- 显式提供的测试 fixture；
- 已有 `CreateProcess`、`ShellExecute*`、`WinExec` 和
  `CreateProcessAsUser` 请求的统一建模。

首个阶段不以真实 IE、`cmd.exe`、PowerShell 或其他宿主程序执行为目标。

## 2. 非目标

以下内容不属于第一阶段：

- 调用宿主机 `CreateProcess`、`system()`、`subprocess` 或 shell；
- 执行网络下载得到的未知字节；
- 自动下载或复制真实系统 EXE/DLL；
- 把 URL、文档、快捷方式或脚本错误地当成 PE；
- 通过 shell file association 启动真实浏览器；
- 默认递归到 depth=2；
- 声称已经实现完整 Windows 进程地址空间隔离；
- 让 child timeout、非法读或 unsupported API 改变原本正常的父样本 outcome；
- 仅凭 `ShellExecute`/`WinExec` 返回成功就标记 child 已启动。

## 3. 当前缺口

`3.1` 至 `3.3` 保留修复前的诊断，用于解释为什么不能直接打开
`emulate_children`。阶段 1 之后的真实状态和剩余缺口见 `3.4`。

### 3.1 请求入口不完整

| 入口 | 当前行为 | 问题 |
|---|---|---|
| `ShellExecute` | 调用 `create_process()`，未传 `child=True` | 进程进入普通 `processes`，不进入 child 队列 |
| `ShellExecuteEx` | 转调 `ShellExecute` | 继承相同问题 |
| `WinExec` | 直接取命令行首 token，调用 `create_process()` | 未传 `child=True`；目标不存在时仍返回 `32` |
| `CreateProcess` | 调用 `create_process(child=True)` | 只进入简单 child 队列，没有策略、深度或预算 |
| `CreateProcessAsUser` | 调用 `create_process()`，未传 `child=True` | 同样不会进入 child 队列 |

关键位置：

```text
speakeasy/winenv/api/usermode/shell32.py
  ShellExecute / ShellExecuteEx

speakeasy/winenv/api/usermode/kernel32.py
  WinExec / CreateProcessInternal / CreateProcess

speakeasy/winenv/api/usermode/advapi32.py
  CreateProcessAsUser
```

### 3.2 `create_process()` 只创建对象

当前 `WindowsEmulator.create_process()` 会：

1. 创建 `Process` 和首个 `Thread`；
2. 尝试取得目标 PE 数据或调用 `load_module_by_name()`；
3. 将入口地址写入线程上下文；
4. 将 Process 放入 `processes` 或 `child_processes`。

它不会：

- 验证目标是否来自允许的字节来源；
- 区分“目标缺失”和“模块已解析”；
- 将 child 线程真正加入 `run_queue`；
- 应用 child depth、数量、时间或 API 预算；
- 生成供报告关联的稳定 `launch_id`；
- 隔离 child 错误和父样本错误。

尤其是目标文件不存在时，`load_module_by_name()` 仍可能返回 decoy
或合成模块。因此不能把 `Process` 对象出现等同于目标已解析。

### 3.3 现有 `emulate_children` 循环不可直接启用

现有 `Win32Emulator.run_module(..., emulate_children=True)`：

- 只处理已经进入 `child_processes` 的请求；
- 在父执行结束后按 FIFO 执行；
- 直接调用高层 `load_module(data=child.pe_data)`；
- 没有 target resolution 和 eligibility；
- 没有 child run deadline、API 或指令预算接口；
- 没有递归停止条件；
- 没有独立的 child outcome；
- 没有稳定的事件 ownership；
- 可能覆盖根样本 metadata，因为高层 `load_module()` 会重新设置
  profiler 的 input metadata；
- 可能把 child 在 `load_image()` 中当成主模块处理，影响静态字符串、
  stack 和主模块语义。

因此，不能只做下面两件事：

```python
# 错误方案：只修 API 参数
emu.create_process(..., child=True)

# 错误方案：只打开现有开关
engine.run_module(module, emulate_children=True)
```

必须先增加受控执行协调器。

### 3.4 阶段 1 当前状态

阶段 1 的 model-only 代码已经落地，但尚未提交：

- 四类进程 API 已统一记录 request；
- target 来源和 PE admission 已建模；
- `launch_id`、parent/child pid、target/command hash、depth 和原因已写入报告；
- `run_module(emulate_children=True)` 不会执行 child；
- `ResumeThread`、`CreateRemoteThread` 和 child thread 的
  `QueueUserAPC` 已被 model-only policy 阻断；
- 报告中的 `execution_enabled=false`、`thread_queued_count=0`、
  `entrypoint_reached_count=0`。

当前仍未实现：

- 合格 request 的专用 child loader 和独立 run context；
- child scheduler、独立 budget 和递归停止；
- child 入口 hook、事件 ownership 和 child outcome；
- dynamic stage / shell tracker 对引擎权威结果的消费；
- 1,229 model-only 全量回归。

## 4. 必须维持的不变量

实现和评审都应逐条检查以下不变量：

1. 宿主机不得创建或执行目标进程。
2. 父样本的 `status`、`coverage` 和根 metadata 不得被 child 结果覆盖。
3. `Process`、`Thread`、`target_resolved`、`thread_queued` 和
   `entrypoint_reached` 是不同事实，不能互相推断。
4. process request 成功不等于 child 执行成功。
5. child 只能使用 `self`、完整 `dropped_file` 或显式 `fixture` 字节。
6. target 必须是完整、可解析、可执行且与 engine 架构一致的 PE。
7. 同一个 root 上的 child 数量、总时间和递归深度有硬上限。
8. child 的错误只归属于 child，除非独立检测器明确把 child 证据提升为父样本 finding。
9. 所有 child 事件必须能通过 `root_sample_sha256`、`parent_pid`、
   `child_pid`、`depth` 和 `launch_id` 回溯。
10. 任何 unavailable、ineligible 或 skipped 状态都必须留下原因，不能静默丢弃。
11. child 的启动顺序和 admission 结果必须可复现。
12. 默认行为保持关闭；启用必须显式传入策略。

## 5. 总体架构

```text
process-launch API
  -> ChildRequestRecorder
       - 保存 source API、target、command line、parent context
       - 解析目标字节
       - 生成 launch_id
  -> ChildAdmissionPolicy
       - PE / 架构 / 来源 / depth / count / duplicate
  -> Process + Thread creation
  -> ChildExecutionQueue
       - 父模块执行结束后才 drain
  -> ChildRunner
       - 独立 current process/thread/run context
       - 继承 parent 的限额，使用 child 独立计数
       - entrypoint 到达确认
  -> ChildExecutionResult
  -> Report + dynamic stage correlation
```

建议新增一个边界清晰的协调模块，例如：

```text
speakeasy/windows/child_execution.py
```

该模块保存策略、请求、结果和 scheduler；API handler 只负责解析参数并调用统一入口，避免五个进程 API 各自复制一套逻辑。

## 6. 生命周期状态机

每个 request 使用下面的单向状态：

```text
requested
  -> target_resolved
       -> eligible
            -> process_object_created
                 -> thread_queued
                      -> entrypoint_reached
                           -> completed | partial | failed
       -> skipped
  -> unavailable
  -> rejected
```

状态字段至少包括：

| 字段 | 含义 |
|---|---|
| `requested` | API 参数已经解析并记录 |
| `target_resolved` | 找到了允许来源的字节，并完成目标身份计算 |
| `eligible` | PE、架构、来源、depth、count 和去重均通过 |
| `process_object_created` | 已创建 fork 的 `Process`/`Thread` 对象 |
| `thread_queued` | child entry run 已加入执行队列 |
| `entrypoint_reached` | one-shot 入口 hook 已确认执行到 child 入口 |
| `completed` | child run 在预算内正常返回/退出 |
| `partial` | 执行过入口，但因预算或可解释的运行错误提前结束 |
| `failed` | 入口前加载、排队或上下文初始化失败 |
| `skipped` | 请求合法但策略明确不执行，例如 URL、fixture missing、depth limit |
| `unavailable` | 目标路径没有可获得的完整字节 |
| `rejected` | 目标存在但不满足安全性或解析要求 |

`entrypoint_reached` 必须由 child 入口地址的一次性 code/instruction hook
确认。不能使用以下替代证据：

- API 返回成功；
- 创建了 Process 对象；
- 创建了 Thread 对象；
- 将 run 放进了队列；
- child 在尚未执行时被报告为 timeout。

## 7. 核心数据合同

### 7.1 ChildExecutionRequest

建议使用 dataclass 或独立 Pydantic 模型，至少包含：

```text
launch_id
source_api
parent_pid
parent_tid
parent_launch_id
root_sample_sha256
depth
requested_target
normalized_target
working_directory
command_line
command_sha256
target_source
target_sha256
target_size
target_format
target_arch
target_module_type
target_bytes_ref
process_object_created
created_child_pid
target_resolved
eligible
thread_queued
entrypoint_reached
skip_reason
rejection_reason
```

`launch_id` 应由引擎在 request 创建时生成，不能等到 shell detector 阶段再根据 call index 生成。detector 必须接受并保留引擎给出的 ID。

`parent_launch_id` 在根样本直接发起时为空；child 自己再发起进程请求时，其值为当前 child 的 `launch_id`。

### 7.2 ChildExecutionResult

至少包含：

```text
launch_id
parent_pid
child_pid
root_sample_sha256
depth
state
outcome
termination_reason
coverage
api_count
instruction_count
wall_time
run_indexes
error
```

建议的 `outcome`：

```text
ok
partial
error
skipped
unavailable
rejected
```

建议的 `termination_reason`：

```text
normal_exit
returned_to_caller
timeout
max_api_count
max_instructions
depth_limit
child_count_limit
duplicate_launch
target_unavailable
target_not_pe
arch_mismatch
entrypoint_missing
load_error
invalid_fetch
internal_error
```

### 7.3 报告落点

推荐同时保留两个层次：

1. child 的实际 Run 继续进入 `report.entry_points`，因为这样已有的 API、
   file、registry、network、memory 和 dropped-file 事件可以复用；
2. 顶层增加 `child_execution` 汇总，保存 policy、request、result 和
   `launch_id -> run_index` 映射。

每个 child Run 和其中的事件应增加可选 ownership 上下文：

```text
root_sample_sha256
parent_pid
child_pid
depth
launch_id
```

`pos.pid` 仍表示事件发生时真正活动的执行进程。ownership 是额外的链关系，不应覆盖 `pos.pid`。

父样本的顶层 `sha256`、`filepath`、`size`、`arch` 和 `image_base` 必须始终指向根输入。

## 8. 目标解析

目标解析必须在创建可执行 child 之前完成。

### 8.1 支持顺序

按以下顺序解析，并记录最终命中的来源：

1. `self`
   - 规范化 target 的 basename、stem 和路径；
   - 与根样本 basename/stem/SHA 相符时，绑定父样本的原始 PE 字节；
   - 不能绑定父进程运行中被修改过的内存副本。
2. `dropped_file`
   - 只接受仿真文件系统中已经完整写入的 dropped file；
   - 在 admission 或执行前校验 SHA-256，避免后续改写；
   - 不完整写入的文件返回 `target_unavailable`。
3. `fixture`
   - 只从显式配置的 target/hash 映射读取；
   - 不按任意宿主机路径搜索；
   - fixture 必须记录来源和预期 SHA-256。
4. 其他系统映像或 shell association
   - 第一阶段返回 `fixture_required` 或 `non_pe_target`；
   - 不调用真实系统程序。

### 8.2 路径规范化

解析器至少处理：

- 引号；
- `Sysnative`、`System32` 和 Windows 大小写不敏感路径；
- `%SystemRoot%`、`%WINDIR%` 等仿真环境变量；
- `CreateProcess` 的 `lpCurrentDirectory`；
- `ShellExecute` 的 `lpDirectory`；
- 无扩展名 self target；
- NT 路径与 Win32 路径的明确转换。

不能仅凭 basename 在 dropped files 中模糊匹配，否则同名文件会被错误执行。

### 8.3 禁用现有 fallback

child 请求不能通过以下兜底获得“可执行目标”：

- `load_module_by_name()` 的 decoy 模块；
- `functions_always_exist` 产生的合成模块；
- `by_ext` 下的 `default.bin`；
- 网络响应字节；
- 宿主机上恰好存在的同名文件。

这些机制可用于普通 API emulation，但不能证明一个 child PE 已被解析。

## 9. Admission 规则

第一版建议采用全部满足才执行：

| 条件 | 规则 |
|---|---|
| 来源 | `self`、`dropped_file`、`fixture` |
| 完整性 | 文件已有完整字节，target SHA 可计算 |
| 格式 | 完整可解析 PE |
| 类型 | EXE；第一阶段不把 DLL 当独立进程执行 |
| 入口 | 有非零入口点且位于镜像范围 |
| 架构 | 与 engine 当前架构一致 |
| 大小 | 不超过显式配置的 target byte 上限 |
| 深度 | `depth <= max_depth` |
| 数量 | 未超过每个 root 的 child 上限 |
| 去重 | 未执行过相同 `target_sha256 + canonical_command` |
| 策略 | `child_execution.enabled=True` |

建议初始保护值：

```text
max_depth = 1
max_children_per_root = 4
child.timeout = parent.timeout
child.max_api_count = parent.max_api_count
child.max_instructions = parent.max_instructions
```

`max_depth` 和 `max_children_per_root` 是调度保护值，不是检测阈值。
child 的三项运行预算必须与 parent 启动时使用的配置值一致，不能另设更小的
隐藏默认值，也不能用 child 专用常量覆盖父样本配置。

后续只有在 depth=1 的收益、成本和误报都可接受时，才允许测试 depth=2。

## 10. 调度与预算隔离

### 10.1 执行时机

父样本正常进入 `run_module()` 后：

1. API handler 记录 request；
2. admission 生成可执行或 skipped 结果；
3. 父样本完成其现有 run queue；
4. child scheduler 才 drain child queue；
5. 每个 child 在一个独立的 child run 中执行；
6. child 发起的 grandchild request 只记录，并按 depth 策略拒绝；
7. 所有 child 结束后统一生成报告。

这条规则确保 child 不会在父 API handler 的调用栈中同步执行，也不会改变父 API 的返回路径。

### 10.2 child 预算继承

child 与 parent 使用**相同的预算限额**：

```text
child.timeout_seconds = parent.timeout_seconds
child.max_api_count = parent.max_api_count
child.max_instructions = parent.max_instructions
```

这里的“相同”指三个限额值逐项一致，不表示共享同一个消耗计数器。parent 和每个
child Run 都必须有独立的已用时间、API count 和 instruction count；某个 child
耗尽预算只能结束该 child。

根样本开始执行时，从不可变配置构造一次预算快照：

```python
@dataclass(frozen=True)
class ExecutionBudget:
    timeout_seconds: float
    max_api_count: int
    max_instructions: int
```

child scheduler 必须通过已声明的接口取得 `ExecutionBudget`，并为每个 child
创建等值预算。禁止通过临时修改 frozen config、覆盖实例属性、生产代码
monkey patch 或依赖 `getattr` 隐式回退来“借用”父配置。

公共接口和运行结果必须明确记录：

```text
budget_source = parent_config
timeout_seconds_limit
max_api_count_limit
max_instructions_limit
timeout_seconds_used
api_count_used
instruction_count_used
```

至少需要覆盖：

- `WindowsEmulator._execute_runs()` 的 wall-clock timeout；
- `WindowsEmulator.handle_import_func()` 的 API count；
- instruction budget 检查和 `instruction_budget_exhausted`；
- child deadline 到达后的 `stop()`；
- `on_run_complete()` 后不继续运行被拒绝的 grandchild。

parent timer 和 child timer 使用相同限额但独立计时。child timeout 只能设置
child result，不能设置父样本的 `timed_out`。若批次 owner 或 parent 被外部
stop，按 `10.3` 停止 child；这属于上级生命周期终止，不是降低 child 的预算值。

### 10.3 全局停止

如果父样本自身被外部 owner timeout 或 stop：

- 尚未开始的 child 统一标记为 `skipped: parent_stopped`；
- 正在执行的 child 停止；
- 已完成的 child 保留已有证据；
- 父样本的 termination reason 不被 child 覆盖。

## 11. 进程上下文与运行入口

child 执行前必须显式建立并恢复上下文：

```text
save parent current_process/current_thread/current_run
  -> clear/select child run queue
  -> set child process and thread
  -> allocate/reuse child PEB and TEB as required
  -> set run.process_context and run.thread
  -> queue child entry run
  -> install one-shot entrypoint hook
  -> execute
  -> record result
  -> restore parent context
```

### 11.1 专用 child loader

不要调用高层 `Win32Emulator.load_module()` 来加载 child，因为它会：

- 重新设置 `_init_name()`；
- 将 child 字节加入 files；
- 覆盖 `self.input` 和 profiler 根 metadata；
- 设置主模块 stack 和 return context。

建议实现专用 loader：

```text
load_child_image(request, primary=False)
```

它应：

- 直接用 `PeLoader` 构建 `LoadedImage`；
- 使用唯一、可审计的 child emu path；
- 调用较低层 `load_image()` 并明确标记 `primary=False`；
- 保留父样本 metadata；
- 为 child 建立独立 Run；
- 不把 child 的静态字符串追加成根样本静态字符串。

现有 `load_image()` 需要显式区分 primary 和 child，不能继续以
“loader 是 PeLoader”判断主模块。

### 11.2 地址空间限制

当前 Speakeasy 在一个 engine 中共享全局 memory map、objects、files、
registry 和 network managers。第一阶段可在同一 engine 中创建逻辑 child
process context，但不能宣称拥有完整 Windows 地址空间隔离。

因此第一阶段报告必须明确：

- child 的模块被加载到同一仿真地址空间；
- child 可观察到父样本已经映射的模块和资源；
- child 的 file/registry/network 副作用需要 ownership 标记；
- 不能回滚的共享状态必须在限制字段中声明。

测试中应至少覆盖两个 sibling child，确认以下内容仍然独立：

- pid；
- run index；
- API/instruction budget；
- termination reason；
- 事件 ownership；
- report 中 `launch_id -> run` 的映射。

若同引擎加载导致不可接受的交叉污染，应把“真实地址空间隔离”作为独立设计任务，而不是在 child scheduler 中隐式实现。

## 12. API handler 改造约束

### 12.1 统一入口

所有进程启动 API 应通过同一个方法，例如：

```text
emu.request_process_execution(
    source_api,
    path,
    cmdline,
    cwd=...,
    creation_flags=...,
    parent_context=...,
)
```

handler 负责参数解码和返回值格式，引擎负责 target resolution、admission、
Process/Thread 创建、排队和报告。

### 12.2 返回值语义

- `CreateProcess`/`CreateProcessAsUser` 只有在目标可解析且进程对象可创建时返回成功；
- `WinExec` 只有在目标解析和 process request 成功时返回 `>31`；
- `WinExec` 目标不存在时应返回失败并设置合理 last error，不能继续返回 `32`；
- `ShellExecute` 的合法 URL/association 请求可保留 shell 请求事实，但
  child executor 必须标记 `non_pe_target` 或 `fixture_required`；
- 缺失文件路径的 `ShellExecute` 不得通过 decoy 获得虚假成功；
- `ShellExecuteEx` 必须与底层请求结果保持一致；
- `PROCESS_INFORMATION` 中的 pid/handle 只能在对应对象真实创建后写出。

### 12.3 命令解析

不能继续用简单的 `cmd.split()[0]` 作为所有 API 的 target：

- 带空格和引号的可执行文件路径必须正确解析；
- `CreateProcess` 的 `lpApplicationName` 优先于命令行首 token；
- `lpApplicationName` 为空时才按 Windows 命令行语义解析；
- target、完整 command line、cwd 和 SHA 分别保存；
- 不能为了得到 target 而截断完整 command line。

## 13. 报告与 dynamic stage 对接

### 13.1 父/child outcome 分离

最终报告至少包含：

```text
parent_status
parent_coverage
child_status
child_termination_reason
child_coverage
child_failure_kind
```

如果 child timeout：

- parent 可以保持 `ok`；
- child result 为 `partial` 或 `error`，原因为 `timeout`；
- parent coverage 不因 child coverage 增加而变成完整；
- finding 可以引用 child evidence，但必须说明证据来自哪个 launch。

### 13.2 Shell tracker

现有 shell tracker 应改为消费引擎的 request/result：

- `launch_id` 使用引擎 ID；
- `parent_pid` 使用 request 创建时的当前 pid；
- `child_pid` 使用创建后对象 pid；
- `child_started` 只在 `entrypoint_reached=true` 时为真；
- `child_emulated` 需要 child run 实际结束；
- `coverage` 使用 child outcome 和 coverage，而不是“出现过后续 API”即推断；
- 同一 `launch_id` 不得在 tracker 中重新编号。

### 13.3 dynamic pipeline

`src/dynamic_stage_new/pipeline.py` 当前调用：

```python
engine.run_module(module)
```

不能在完成 child coordinator 前只改成：

```python
engine.run_module(module, emulate_children=True)
```

启用顺序应为：

1. 显式构造 child execution policy；
2. 传入 engine；
3. 由 engine/report 提供 child summary；
4. pipeline 分开收集 parent runtime errors 和 child runtime errors；
5. shell tracker 根据 result 更新 launch；
6. 只有通过验收后才默认在批量任务中开启。

## 14. 建议文件改动范围

代码实现阶段可按以下边界组织：

| 文件/模块 | 责任 |
|---|---|
| `speakeasy/windows/child_execution.py` | request、policy、state machine、queue、result |
| `speakeasy/windows/winemu.py` | target resolver、process request、child loader、owner 状态 |
| `speakeasy/windows/win32.py` | 父执行结束后的 child scheduler、context 切换 |
| `speakeasy/config.py` | child policy 配置与校验 |
| `speakeasy/profiler.py` | Run ownership、budget、report 映射 |
| `speakeasy/report.py` | `child_execution` 汇总和 ownership 字段 |
| `speakeasy/profiler_events.py` | ownership 的可选 schema 扩展 |
| `shell32.py` / `kernel32.py` / `advapi32.py` | 统一请求入口、返回语义、pid 回填 |
| `src/dynamic_stage_new/pipeline.py` | policy 接入、父/child error 分流 |
| `src/dynamic_stage_new/suspicious_shell_behavior_detection/` | 使用权威 launch/result，不自行推断执行 |

### 14.1 模块化实现约束

后续实现必须遵守以下约束：

1. 在对应模块中显式声明 dataclass、枚举、Protocol 或公共方法签名；
2. scheduler、runner、clock、budget factory 和 report adapter 通过构造参数或
   已声明接口协作，不依赖模块间隐式属性；
3. 所有公共类、公共方法和非显然状态字段都要有类型标注和 docstring；
   注释说明预算来源、ownership、错误边界和生命周期；
4. 生产代码禁止 monkey patch、替换实例方法、动态注入未声明属性，以及为了
   通过当前样本而添加的临时私有 hook；
5. 测试使用显式 fake/stub 或依赖注入；不得依赖生产代码中的测试专用分支；
6. 预算、launch id、pid 和 outcome 只能由声明的接口产生或更新，不能在
   detector、pipeline 或脚本中用猜测补齐；
7. API 改动必须限制在已有 handler 的统一 request 入口，不在多个 handler 中
   复制预算和调度逻辑；
8. 每个工作包单独提供测试，不在无关模块中夹带“顺手修改”；
9. 公共报告字段保持向后兼容，新增字段必须注明来源、含义和缺失时的行为。

## 15. 当前工作包与实施顺序

### 15.1 当前证据和状态

`dev2.md` 的最新复跑记录为：

- 1,229 个样本；
- 96 次 process launch 请求，涉及 81 个样本；
- 实际 child execution 为 0；
- 8 个 `mira` self-relaunch；
- 6 个 `padodor` 随机 System32 目标；
- 2 个 `systex` IE + URL 请求和 1 个额外 IE shell 请求；
- 35 个 R3 dropped-file 执行链，其中 2 个是良性安装器。

`dev2.md` 中“16 个 ShellExecute/WinExec 请求”与
`8 + 6 + 2 + 1 = 17` 的计数口径不同。后续统计必须明确单位是样本数、
request 数、API 调用数还是机制分类数。

阶段 1 model-only、步骤 1-5 的引擎侧模块和生产 child scheduler 已经实现；
pipeline 接入与 1,229 全量验收尚未完成。当前策略仍只记录
request，不执行 child。后续工作按下列 A-H 工作包推进。

当前 model-only 代码中的 `per_child_timeout_sec`、
`per_child_max_api_count` 和 `per_child_max_instructions` 仍是旧的设计期
占位字段，不是最终预算定义。实现工作包 D 时必须通过显式
`ExecutionBudget` 接口替换为 parent 同额预算，并在启用 child execution 前
删除或废弃这些 child 专用默认值；它们不得被 runner 直接消费。

### 15.2 工作包 A：稳定 request 和 target 合同

目标：runner 只消费经过统一验证的 request，不直接读取裸 Process 对象。

- request 保存不可变目标快照或可校验的 `target_bytes_ref`；
- self target 绑定根样本原始 PE 字节，不绑定运行中被改写的内存；
- dropped file 在执行前再次校验 SHA；
- fixture 只接受精确路径，不按 basename 模糊匹配；
- 保留 `target_resolved`、`eligible`、`process_object_created` 的独立性；
- 没有完整字节的 request 永远不能进入 child queue；
- 清理 resolver 的重复读取，并核对进程对象的有效 pid 字段。

验收：报告能还原 target 来源、hash、格式、架构和拒绝原因；Process 对象存在
不会覆盖 `unavailable/rejected/skipped` 状态。

### 15.3 工作包 B：API 语义和 pid 回填

目标：API 返回值和对象创建保持一致，但 API 成功不等同 child 已执行。

- `WinExec` 目标不存在时不再返回虚假成功；
- `CreateProcess`/`CreateProcessAsUser` 只在目标可解析时写有效
  `PROCESS_INFORMATION`；
- `ShellExecute/ShellExecuteEx` 显式回填 child pid；
- `ShellExecuteEx` 保留自身 `source_api`；
- application name 优先于 command-line 首 token；
- 正确解析带空格和引号的 target；
- 记录 application/commandline mismatch；
- URL、文档、脚本和 shell association 不进入 PE runner。

验收：6 个 `padodor` 显示 `target_unavailable` 且无虚假 child；8 个 `mira`
绑定 self bytes；2 个 `systex` 保留完整 URL 但不默认执行 IE。

### 15.4 工作包 C：child 专用加载与上下文

目标：为 child 建立独立逻辑 run 上下文，不递归复用根模块加载路径。

- 新增 `load_child_image(request, primary=False)` 或等价入口；
- 直接从 request 字节构建 `PeLoader` image；
- 不覆盖根样本 input、SHA、path、filetype 和 image base；
- 不把 child 静态字符串写入根样本静态字符串；
- 建立独立 Process/Thread、PEB/TEB 和入口参数；
- 保存并恢复 parent 的 `curr_process`、`curr_thread`、`curr_run`、
  run queue 和 suspended queue；
- 处理模块基址冲突、import hook 和 TLS callback；
- 明确记录 child load failure；
- 第一阶段保留同 engine 共享地址空间的限制。

验收：child 加载后根报告身份不变；child 有独立 pid/tid；sibling child 不共享
outcome；parent context 可以恢复。

### 15.5 工作包 D：scheduler 和硬预算

目标：把现有简单 child loop 替换为可重放、可停止的受控调度器。

- 父模块完成现有 run queue 后才 drain child queue；
- child 决策使用稳定 FIFO 和确定性 launch 顺序；
- 首轮只用 depth=1，并禁止 depth=2；
- 每个 root 最多 4 个可执行 child；
- 根样本开始时通过声明接口创建不可变 parent budget snapshot；
- 每个 child 的 timeout、API count 和 instruction count 限额与 parent
  逐项相同，不设置 child 专用的小预算常量；
- parent 和 child 使用相同限额但各自独立的已用计数；
- child 结果记录预算来源、限额和实际消耗；
- 相同 target SHA + canonical command 去重；
- child 发起的 grandchild 只记录、不执行；
- parent 被 stop/timeout 时停止 child，但不让 child 覆盖 parent 原因。
- scheduler、clock、budget factory 和 runner 通过显式接口组合，生产代码
  禁止 monkey patch 和动态属性注入。

验收：无无限 self-relaunch；每个 child 的三项预算限额与 parent 完全相等，
但时间/API/instruction 消耗计数彼此独立；每个 child 有唯一终止原因；相同
输入产生相同 request/decision 顺序。

### 15.6 工作包 E：入口确认和事件采集

目标：用真实 hook 证明 child 到达入口，而不是依赖后续 pid 活动。

- 将 child entry run 显式加入 `run_queue`；
- 在规范化入口地址安装 one-shot hook；
- hook 触发后才设置 `entrypoint_reached=true`；
- 分别记录 `thread_queued` 和 `entrypoint_reached`；
- child Run 保存 `process_context` 和 `thread`；
- child API/file/registry/network/memory/dropped-file 事件写入 child run；
- Run 和事件带 root SHA、parent pid、child pid、depth、launch id；
- child 入口前 invalid fetch、unsupported API、budget stop 都有独立原因。

验收：`thread_queued`、`entrypoint_reached`、`child_emulated` 证据不同；
每个 child 事件只回到一个 launch；parent 事件不受污染。

### 15.7 工作包 F：parent/child outcome 和报告

当前状态：引擎侧已完成强类型 child result/ownership/budget/usage/failure
报告和 `ChildExecutionReportProjector`。projector 只复制公共标量，不输出
target bytes 或 Process/Run 对象。

目标：child 失败只影响 child 证据，不改变父样本原本的仿真结果。

- 分别保存 parent/child 的 status、coverage 和 termination reason；
- 保存 child failure kind；
- 建立 `launch_id -> run_index/event ownership` 映射；
- parent runtime errors 不收集 child run errors；
- child 成功不证明 parent coverage 完整；
- child partial/error 不自动把 parent 设为 `simulation_error`/`timeout`；
- 给报告体积、事件数和 target bytes 生命周期设上限；
- 保持 model-only 报告兼容。

验收：child timeout 时 parent 可以保持 `ok`；batch result 能聚合两层状态。

### 15.8 工作包 G：dynamic stage 和 shell tracker 对接

当前状态：引擎侧已完成 `DynamicChildExecutionAdapter`，它只接受公共
`ChildExecutionReport`，校验 lineage 后调用 tracker 的显式
`update_child_execution(report)`。真实 dynamic-stage tracker 的该方法、
pipeline 注入和旧 `note_execution_context` pid 推断替换留到后续集成，不能
通过修改 `kernel32.py` 或其它仿真路径绕接。

目标：下游消费引擎权威 request/result，不自行推断执行事实。

- `launch_id` 以引擎生成为准；
- tracker 不再按 call index 重编号；
- `process_object_created` 不从 API 返回码推断；
- `child_started` 只由 `entrypoint_reached` 驱动；
- `child_emulated` 只由 child run 实际结束驱动；
- `child_pid` 使用创建对象后的显式回填值；
- pipeline 收集 `Report.child_execution`；
- child errors 和 parent errors 分开；
- 保留现有 command、URL 和 review signal 合同；
- 小批使用显式开关，不直接改变 1,229 默认批次。

验收：tracker 字段逐项可追溯；`target_resolved=false` 的 Process 对象不会
被标为 child started；batch summary 包含 request、queued、entrypoint、
completed、partial、skipped 和 rejected。

### 15.9 工作包 H：分阶段实验与回归

1. 1,229 model-only 回归：父样本继续执行，child execution 必须为 0；
2. 8 个 `mira` self-relaunch：depth=1，验证入口、pid、ownership 和递归停止；
3. 完整 dropped EXE 小批：从 R3 链选择，同时监控 2 个良性安装器；
4. 6 个 `padodor`：验证 unavailable 和 API 失败语义；
5. 2 个 `systex`：保持 target/URL，不默认执行 IE；
6. fixture 评估：只有证据要求时才考虑最小 IE/cmd/PowerShell runtime；
7. depth=2 决策：只在 depth=1 的收益、成本、噪声和误报均可接受后开放。

验收指标：

| 测试组 | 必须验证 |
|---|---|
| 1,229 model-only | request 字段不回退；child execution 为 0 |
| 8 个 `mira` | self bytes 正确；入口真实；递归停止 |
| 6 个 `padodor` | unavailable；无 child；API 不虚假成功 |
| 2 个 `systex` | URL/target 完整；无默认 IE 执行 |
| R3 完整 dropped EXE | source/hash/ownership 完整 |
| 2 个良性安装器 | parent status 不被 child 噪声覆盖 |

2026-11-06 小批实验结果：state-only 重跑 12 个样本全部 `ok`，但真实
child execution 仍被生产 scheduler/pipeline 接线阻断。`mira` self-target
4/4 未解析，`padodor` 6/6 仍表现为虚假成功，因此 depth=2 未获批准。
完整证据见
[step6_experiments/README.md](step6_experiments/README.md)。

### 15.10 依赖关系和阶段顺序

```text
A request/target
  -> B API semantics/pid
  -> C child loader/context
       -> D scheduler/budget
            -> E entrypoint/ownership
                 -> F outcome/report
                      -> G dynamic stage
                           -> H experiments
```

A 和 B 可以在不执行 child 的情况下完成。C 完成后才具备打开执行开关的条件。
实际 rollout 顺序仍为：

1. state-only regression；
2. `mira` self + depth=1；
3. 完整 dropped EXE；
4. `padodor` 失败语义；
5. `systex` / IE fixture 决策；
6. depth=2 决策。

## 16. 测试计划

### 16.1 单元测试

必须覆盖：

- self target 的无扩展名、大小写和路径 aliases；
- relative path + cwd；
- dropped file 完整/不完整；
- fixture 命中/未命中；
- missing file 不通过 decoy fallback；
- PE corruption、非 PE、DLL、driver、entrypoint missing；
- x86/x64 architecture mismatch；
- depth、count、duplicate 和 source policy；
- 所有进程 API 的返回值语义；
- `PROCESS_INFORMATION` 写出条件；
- child pid 在 `create_process()` 后回填；
- state machine 不允许跳级；
- ownership schema 的前后兼容；
- root metadata 在 child load 后不变。

### 16.2 Runner 集成测试

使用小型合成 fixture 覆盖：

1. child entry 调用一个已知 API；
2. child 正常 return；
3. child 在入口前 invalid fetch；
4. child timeout；
5. child 达到 parent 配置的 `max_api_count`；
6. child 达到 instruction cap；
7. child 再启动同一 self target；
8. 两个 sibling child；
9. child exit 后 parent context 恢复；
10. child 的 run/event 带正确的 parent pid、child pid 和 depth。

测试中的 clock、runner 和 API sink 应通过显式 fake/stub 或依赖注入构造，
确认不会调用宿主 `CreateProcess`、shell 或 subprocess；生产代码不得依赖
monkey patch。另需用非默认 parent 配置验证 child 的 timeout、API count 和
instruction limit 三项都与其逐项相等，而消耗计数分别独立。

### 16.3 样本回归

| 样本组 | 预期 |
|---|---|
| 8 个 `mira` | target 解析为 self；allow 的请求进入 queue；真实记录 entrypoint |
| 6 个 `padodor` | random System32 路径 unavailable；无首次执行；API 不虚假成功 |
| 2 个 `systex` | URL 和 IE target 保留；无 fixture 时 `fixture_required` |
| 35 个 R3 dropped chain | 只有完整 dropped EXE 可执行；source 和 hash 可回溯 |
| 2 个良性安装器 | child 行为不被直接判恶；父/child 状态分离 |

## 17. 验收标准

满足以下条件才算完成受控 child execution 的第一轮修复（不仅是阶段 1）：

1. `ShellExecute`、`ShellExecuteEx`、`WinExec` 和
   `CreateProcessAsUser` 的请求都能进入统一 child request 模型。
2. 8 个 `mira` 的 self target 能解析到根样本原始 PE；
   是否到达入口必须由 hook 真实确认。
3. target 不存在、非 PE、架构不匹配和 depth 超限时有稳定原因，
   不创建虚假的可执行 child。
4. child 在父执行结束后按有界策略运行。
5. child 的 timeout/API/instruction 限额与 parent 相同、消耗计数独立，
   父 outcome 不被覆盖。
6. same target + command 不会无限 self-relaunch。
7. child 事件可通过五个 ownership 字段回溯到唯一 launch。
8. 根样本 metadata 和顶层 report identity 不变。
9. child state 不依赖 detector 的二次猜测：
   `entrypoint_reached`、`thread_queued` 和 `child_started` 都有明确来源。
10. 全量 1,229 样本在 child execution 关闭时与修复前基线一致；
    开启后不出现宿主进程或错误采样。
11. 针对新增逻辑的单元、集成和回归测试通过。

## 18. 已知限制和待决策项

### 18.1 同引擎共享状态

第一阶段使用同一 engine 的逻辑 child context，不能回滚父进程已经造成的
global memory、object、file、registry 和 network 状态。报告必须保留这一限制，
不能把“有独立 pid”误写成“完整进程隔离”。

### 18.2 同额预算带来的总运行时间

每个 child 继承 parent 的同一组预算限额，因此多个 child 的累计 wall-clock
时间可能超过单个 parent。第一版通过 `max_children_per_root=4`、depth=1、
去重和批次 owner 的整体超时控制放大范围；这些调度限制不得被实现成对 child
单个运行预算的静默缩减。

如果 `parent.max_instructions=-1`，child 也必须继承 `-1`。若流水线不接受
无指令上限，应在上层配置中显式设置 parent 的值，再由 child 继承；不能在
child runner 内私自替换为其他常量。

### 18.3 浏览器/脚本 fixture

真实浏览器路径、TLS、JavaScript、COM 和 GUI runtime 成本高。是否加载最小
fixture 应由 URL/command evidence 与命中收益决定，不能作为默认 child 能力。

### 18.4 地址空间隔离

如果后续证明共享地址空间会污染 self-relaunch 或 sibling child，应单独设计
per-process memory map/object namespace。不要把这项高风险改动混入第一轮
target resolution 和 launch tracking 修复。

## 19. 实施前检查清单

- [x] 当前修复前基线仍为 `b970251`。
- [x] 阶段 1 model-only request 和报告已实现。
- [x] 明确 `emulate_children=True` 不是完整修复本身。
- [x] target resolver 不经过 decoy/default.bin fallback。
- [x] API success、Process、queue 和 entrypoint 分别建模。
- [ ] 完成 1,229 样本 model-only 全量回归。
- [x] 完成 child loader、context manager、one-shot 入口 hook 和 runner 的
      独立实现；真实 scheduler 接入仍未完成。
- [x] child loader 使用显式 base allocator、`primary=False` 映射，并保留
      root metadata。
- [x] child runner 使用与 parent 等额但独立的 usage 计数，并将预期 child
      错误收口为 child result。
- [x] 完成生产 child scheduler：FIFO、parent 完成后 drain、停止传播、
      独立 usage、child-local failure 和不可变报告快照均通过显式接口测试。
- [ ] 完成真实 emulator/pipeline 端到端接入。
- [ ] policy 默认关闭，depth/count 有上限，time/API/instruction 继承 parent。
- [x] 所有步骤 4 新增协作者通过显式接口注入，生产代码无 monkey patch。
- [x] parent metadata 不被 model-only child load 覆盖。
- [x] child run 的 parent/child status 和 error 有独立保护。
- [ ] detector 接受权威 `launch_id` 和 child result。
- [x] 先跑 state-only 回归：12 个样本全部 `ok`，child started/emulated 为 0。
- [x] 完成 `mira` model-only 门槛复核：4 个真实 launch 均未解析为 self。
- [ ] 真实 `mira` child execution：被 pipeline 接线阻断。
- [x] 完成 R3 dropped artifact 清单及两个良性安装器标记。
- [ ] 真实 dropped EXE child execution：被生产路径映射和 pipeline 接线阻断。
- [ ] depth=2：未获批准。
