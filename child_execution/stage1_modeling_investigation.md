# 阶段 1 调查与实现结论：只建模，不执行

## 1. 结论

阶段 1 已按 `child_execution_capture_develop_manual.md` 落地为 model-only 边界：

- 四类进程启动 API 统一记录 child request；
- target 只从根样本、已完整落盘的 dropped file 或显式 fixture 解析；
- admission 覆盖 PE、EXE、入口点、架构、来源、大小、depth、数量和去重；
- 记录 `target_resolved`、`process_object_created`、skip/rejection reason；
- 报告增加顶层 `child_execution` 汇总和 child ownership schema；
- child execution 始终关闭，不向 `run_queue` 添加 child run。

该阶段只回答“请求了什么、目标是谁、是否允许进入后续执行”，不声称 child
已经启动或执行。

## 2. 实际调用链

```text
ShellExecute / ShellExecuteEx
WinExec
CreateProcess / CreateProcessInternal
CreateProcessAsUser
  -> WindowsEmulator.request_child_process()
  -> ChildExecutionRegistry.create_request()
  -> ChildTargetResolver.resolve()
  -> Process object retained for legacy API compatibility
  -> no child run queued

emulator.get_report() / get_json_report()
  -> ChildExecutionRegistry.to_report_dict()
  -> Profiler.meta["child_execution"]
  -> Report.child_execution
```

关键位置：

- `speakeasy/windows/child_execution.py:39`：policy、状态、request、resolver、registry；
- `speakeasy/windows/winemu.py:1453`：统一 process request 入口；
- `speakeasy/windows/win32.py:301`：父 module 完成后禁止 drain child queue；
- `speakeasy/windows/win32.py:369`：把 request summary 注入报告；
- `speakeasy/winenv/api/usermode/kernel32.py:857`：`WinExec`；
- `speakeasy/winenv/api/usermode/kernel32.py:973`：`CreateProcess`；
- `speakeasy/winenv/api/usermode/advapi32.py:1487`：`CreateProcessAsUser`；
- `speakeasy/winenv/api/usermode/shell32.py:107`：`ShellExecute` / `ShellExecuteEx`；
- `speakeasy/report.py:538`：request report；
- `speakeasy/report.py:574`：child execution report；
- `speakeasy/report.py:713`：entry-point ownership；
- `speakeasy/report.py:814`：顶层 report 字段。

## 3. Target 解析

解析优先级固定为：

1. 根样本自身，按根文件 basename/stem/SHA 匹配；
2. 显式注册的 fixture；
3. 仿真文件系统中属于 dropped file 的完整字节；
4. 其他路径记为 `target_unavailable`，不搜索宿主文件系统。

URI 记录为 `non_pe_target` 并进入 `skipped`。PE 解析只读取内存中的字节，
不会载入或执行目标入口点。

## 4. Admission

初始策略：

```text
mode = model_only
max_depth = 1
max_children_per_root = 4
max_target_bytes = 64 MiB
per_child_timeout_sec = 5
per_child_max_api_count = 1000
per_child_max_instructions = 1000000
allowed_sources = self, dropped_file, fixture
```

拒绝原因包括：

- `depth_limit`；
- `target_unavailable` / `target_too_large`；
- `target_not_pe` / `target_not_executable`；
- `entrypoint_missing` / `entrypoint_out_of_range`；
- `arch_mismatch`；
- `target_source_not_allowed`；
- `duplicate_launch`；
- `child_count_limit`。

去重身份是 `target_sha256 + canonical command hash`。canonical command 只收敛
空白和参数外围引号，不重排参数，也不对参数大小写折叠。

## 5. 不执行不变量

阶段 1 必须同时满足：

```text
execution_enabled = false
thread_queued_count = 0
entrypoint_reached_count = 0
```

当前保护点：

- `ChildExecutionRegistry.allow_execution` 恒为 `False`；
- `run_module(emulate_children=True)` 只记录 warning，不 drain child queue；
- `ResumeThread` 不把 child 线程加入运行队列；
- `CreateRemoteThread` / `QueueUserAPC` 拒绝针对 child process/thread 的注入；
- `request_child_process()` 保留 legacy `Process` 对象，但不排队。

## 6. 当前验证

已执行：

```text
pytest -q tests/test_child_execution_model.py
22 passed

ruff check <stage-one changed Python files>
All checks passed

git diff --check
passed
```

额外运行了 API 签名、报告/制品和运行隔离相关测试：

```text
16 passed
1 failed
```

唯一失败为既有 `test_upx_unpack_example_runs_and_dumps_file`：测试样本文
`tests/capa-testfiles/Practical Malware Analysis Lab 01-02.exe_` 在当前工作区
不存在，报错为 `Target file not found`。该失败发生在 emulator load 之前，
与 child execution 修改无关。

## 7. 尚未验证与阶段 2 前置项

阶段 1 没有运行 1,229 个真实样本，因此以下验收仍待批量回归：

- 原有 launch 字段无回退；
- 对 `mira`、`padodor`、`systex` 和 R3 dropped-chain 的 request 分布；
- 报告体积和 target 解析成本；
- Process object 与 target resolution 的语义差异是否被下游正确消费。

阶段 2 开始前必须显式实现 policy 启用和 child scheduler；不能直接打开
`allow_execution`。每个 child 还需要独立 run context、budget、入口 hook、
ownership 事件和错误隔离。

## 8. 有意留到后续阶段

- `WinExec` 目标不存在时的真实返回语义；
- `ShellExecute` / `WinExec` 的 pid 回填；
- `CreateProcessAsUser` 的 legacy child 分类修正；
- application / command-line mismatch 和更多 quoted-path 边界；
- child run 事件归属、budget 统计与 parent outcome 隔离；
- browser/script runtime 和 depth=2。

这些属于手册的阶段 2 至阶段 6，不应混入 model-only 阶段。
