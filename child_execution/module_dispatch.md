# Child execution 模块调度与接口设计

> 日期：2026-11-04
>
> 状态：步骤 1-4 已实现；scheduler 接入和 report/dynamic adapter 尚未实现
>
> 上位设计：
> [child_execution_capture_develop_manual.md](child_execution_capture_develop_manual.md)
>
> 当前阶段 1 记录：
> [stage1_modeling_investigation.md](stage1_modeling_investigation.md)

## 1. 目的

本文定义增加“受控 child process detection/execution”时需要拆出的模块、模块职责、
依赖方向、公共数据结构、接口签名和调度顺序。

这里的目标不是给现有 `emulate_children` 增加几个参数，而是建立一条可以测试、
可以停止、可以审计的行为链：

```text
process-launch API
  -> request creation
  -> target resolution
  -> admission decision
  -> process object creation
  -> queued child launch
  -> child image loading
  -> child process context
  -> bounded execution
  -> run/event ownership
  -> report
  -> dynamic-stage adapter
```

实现时必须先冻结接口，再按模块逐项落地。任何模块都不能通过 monkey patch、
实例方法替换、未声明动态属性或跨模块私有字段修改来补链路。

## 2. 不变量

1. API 请求、目标解析、Process 对象、执行队列、入口点和完成结果是不同事实。
2. 只有 `ChildExecutionDispatcher` 可以把 request 从 admitted 推进到 queued。
3. 只有 `ChildRunner` 可以执行 child；API handler 不得直接调用 child entry。
4. child 的 timeout/API/instruction **限额与 parent 相同**。
5. parent 和每个 child 使用独立的已用时间、API 和 instruction 计数。
6. child 失败不覆盖 parent 状态；parent 失败会停止 child scheduler。
7. 每个 child run 和事件必须具有 `launch_id`、parent/child pid、depth 和 root SHA。
8. 没有完整 target bytes 的 request 不得进入 loader 或 run queue。
9. 生产代码不得调用宿主进程 API。
10. 默认仍为关闭；开启必须通过显式配置和依赖注入。

## 3. 目标模块布局

当前 `speakeasy/windows/child_execution.py` 是单文件 model-only 实现。目标结构建议
迁移为同名 package，并通过 `__init__.py` 保持公共 import 路径不变：

```text
speakeasy/windows/child_execution/
  __init__.py        # 仅导出稳定的公共接口
  models.py          # 不可变数据合同和枚举
  interfaces.py      # Protocol/ABC；模块之间只依赖这里
  request.py         # request 构造、canonical command、launch id
  targets.py         # self/dropped/fixed fixture/unavailable 解析
  policy.py          # admission 和去重
  budget.py          # parent budget snapshot 与 child 等额预算
  runtime.py         # child image loader、Process/Thread 和上下文管理
  scheduler.py       # queue、depth/count、parent/child lifecycle
  runner.py          # child run queue、entrypoint hook 和预算执行
  reporting.py       # ownership、result 汇总和 report adapter
  dispatcher.py      # 唯一编排入口
```

因为 Python 不允许同目录中同时存在 `child_execution.py` 和
`child_execution/`，切换 package 必须作为一次独立、可回滚的重构完成。
`__init__.py` 必须继续导出当前调用方使用的：

```text
ChildExecutionPolicy
ChildExecutionRegistry
ChildExecutionRequest
ChildExecutionState
ChildTargetResolver
ChildTargetSource
```

任何公共符号迁移都要先增加兼容导出，再删除旧文件。

## 4. 模块职责和依赖

| 模块 | 负责 | 不负责 | 允许依赖 |
|---|---|---|---|
| `models.py` | DTO、枚举、状态值、原因码 | I/O、解析、执行 | 标准库 |
| `interfaces.py` | 跨模块 Protocol/ABC | 具体实现 | `models.py` |
| `request.py` | 构造 request、生成稳定 ID、命令规范化 | 读取文件、创建 Process | `models.py` |
| `targets.py` | target 字节解析、PE metadata、来源校验 | admission、执行 | `models.py`、loader |
| `policy.py` | source/depth/count/duplicate/PE admission | 修改队列、执行 | `models.py`、`targets.py` |
| `budget.py` | parent snapshot、child 等额预算、usage 初始化 | 调度、执行 | `models.py` |
| `runtime.py` | child image、PEB/TEB、上下文保存/恢复 | 策略决定、run queue 调度 | `models.py`、engine loader |
| `scheduler.py` | child queue、FIFO、生命周期、停止传播 | 执行 CPU/API | `models.py`、interfaces |
| `runner.py` | run queue、entry hook、预算终止、child result | target policy、报告格式 | `runtime.py`、`budget.py` |
| `reporting.py` | ownership、result/report 映射 | 修改运行状态 | `models.py`、report schema |
| `dispatcher.py` | 唯一编排入口和状态转移 | API 参数解码、CPU 执行细节 | 上述所有已声明接口 |

依赖方向必须保持单向：

```text
API handler / dynamic pipeline
        |
        v
   dispatcher.py
    /   |    \
request targets budget
    \   |    /
      policy
        |
        v
 scheduler.py -> runner.py -> runtime.py
        |             |
        +---- reporting.py
```

`runner.py` 不能反向调用 API handler；`reporting.py` 不能写回 scheduler 状态；
`targets.py` 和 `policy.py` 不得创建或执行 child。

## 5. 核心数据合同

以下类型先定义为 frozen dataclass 或 Pydantic model。字段一旦被实现测试固定，
改动需要版本兼容说明。

### 5.1 ChildExecutionOptions

```python
@dataclass(frozen=True)
class ChildExecutionOptions:
    enabled: bool = False
    max_depth: int = 1
    max_children_per_root: int = 4
    max_target_bytes: int = 64 * 1024 * 1024
    allowed_sources: tuple[ChildTargetSource, ...] = (
        ChildTargetSource.SELF,
        ChildTargetSource.DROPPED_FILE,
        ChildTargetSource.FIXTURE,
    )
```

该配置不包含 child 专用的 timeout/API/instruction 默认值。那三项由
`ExecutionBudget` 从 parent 继承。

### 5.2 ExecutionBudget 和 BudgetUsage

```python
@dataclass(frozen=True)
class ExecutionBudget:
    timeout_seconds: float
    max_api_count: int
    max_instructions: int
    source: Literal["parent_config"] = "parent_config"


@dataclass
class BudgetUsage:
    timeout_seconds_used: float = 0.0
    api_count_used: int = 0
    instructions_used: int = 0
```

不变量：

```text
child_budget.timeout_seconds == parent_budget.timeout_seconds
child_budget.max_api_count == parent_budget.max_api_count
child_budget.max_instructions == parent_budget.max_instructions
child_budget is not parent_usage
```

parent 与每个 child 的 `BudgetUsage` 必须分别创建。

### 5.3 ProcessLaunchSpec

```python
@dataclass(frozen=True)
class ProcessLaunchSpec:
    source_api: str
    target: str | None
    command_line: str
    working_directory: str | None
    creation_flags: int
    requested_show_command: int | None
```

这是 API handler 交给引擎的统一输入。handler 只负责读取参数和将 outcome 映射
成对应 API 返回值，不负责 target resolution、admission 或 child execution。

### 5.4 Engine object protocols

跨模块传递的 engine 对象使用最小 Protocol；不接受匿名 `Any` 或依赖调用方猜测
对象属性。

```python
class EmulatedProcessProtocol(Protocol):
    id: int
    pid: int
    path: str
    cmdline: str
    threads: list["EmulatedThreadProtocol"]


class EmulatedThreadProtocol(Protocol):
    id: int
    tid: int


class EmulatedModuleProtocol(Protocol):
    base: int
    image_size: int
    emu_path: str


class EmulatedRunProtocol(Protocol):
    type: str | int | None
    start_addr: int | None
    process_context: EmulatedProcessProtocol | None
    thread: EmulatedThreadProtocol | None
```

具体 engine 对象可以实现这些 Protocol，但 scheduler、reporting 和 dynamic
adapter 不得访问 Protocol 之外的私有字段。

### 5.5 ChildLaunchRequest

```python
@dataclass(frozen=True)
class ChildLaunchRequest:
    launch_id: str
    root_sample_sha256: str
    parent_launch_id: str | None
    source_api: str
    parent_pid: int
    parent_tid: int | None
    depth: int
    target: str
    normalized_target: str
    working_directory: str
    command_line: str
    command_sha256: str
    parent_budget: ExecutionBudget
```

`launch_id` 由 `ChildRequestFactory` 生成，必须在一次 root emulation 内稳定、
唯一、可排序，不依赖 pid 或 wall-clock。

### 5.6 ChildLaunchRecord

```python
@dataclass(frozen=True)
class ChildLaunchRecord:
    request: ChildLaunchRequest
    target: ResolvedChildTarget | None = None
    decision: AdmissionDecision | None = None
    process: EmulatedProcessProtocol | None = None
    state: ChildExecutionState = ChildExecutionState.REQUESTED
    reason: str | None = None
```

record 由 dispatcher 统一替换，不能由多个模块原地改写。

### 5.7 ResolvedChildTarget

```python
@dataclass(frozen=True)
class ResolvedChildTarget:
    source: ChildTargetSource
    normalized_path: str
    payload_ref: TargetPayloadRef | None
    sha256: str | None
    size: int
    file_format: str
    arch: str
    module_type: str
    entrypoint_rva: int
    resolved: bool
    reason: str | None
```

`TargetPayloadRef` 可以封装内存快照或 artifact ref，但 bytes 不得直接进入报告。

```python
@dataclass(frozen=True)
class TargetPayloadRef:
    source: ChildTargetSource
    sha256: str
    size: int
    emu_path: str
    data: bytes | None = field(default=None, repr=False, compare=False)
```

### 5.8 AdmissionDecision

```python
@dataclass(frozen=True)
class AdmissionDecision:
    eligible: bool
    state: ChildExecutionState
    reason: str | None
```

### 5.9 Outcome、termination 和 failure enums

```python
class ChildOutcome(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    ERROR = "error"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"
    REJECTED = "rejected"


class ChildTerminationReason(str, Enum):
    NORMAL_EXIT = "normal_exit"
    RETURNED_TO_CALLER = "returned_to_caller"
    TIMEOUT = "timeout"
    MAX_API_COUNT = "max_api_count"
    MAX_INSTRUCTIONS = "max_instructions"
    PARENT_STOPPED = "parent_stopped"
    DEPTH_LIMIT = "depth_limit"
    CHILD_COUNT_LIMIT = "child_count_limit"
    DUPLICATE_LAUNCH = "duplicate_launch"
    TARGET_UNAVAILABLE = "target_unavailable"
    TARGET_NOT_PE = "target_not_pe"
    ARCH_MISMATCH = "arch_mismatch"
    ENTRYPOINT_MISSING = "entrypoint_missing"
    LOAD_ERROR = "load_error"
    INVALID_FETCH = "invalid_fetch"
    INTERNAL_ERROR = "internal_error"


class ChildFailureKind(str, Enum):
    TARGET = "target"
    ADMISSION = "admission"
    LOAD = "load"
    CONTEXT = "context"
    SCHEDULER = "scheduler"
    BUDGET = "budget"
    RUNTIME = "runtime"
    INTERNAL = "internal"
```

### 5.10 Process creation 和 launch outcomes

```python
@dataclass(frozen=True)
class ProcessCreationResult:
    process: EmulatedProcessProtocol | None
    created_pid: int | None
    created_tid: int | None
    created: bool
    reason: str | None = None


@dataclass(frozen=True)
class ProcessLaunchOutcome:
    request: ChildLaunchRequest
    resolution: ResolvedChildTarget
    decision: AdmissionDecision
    creation: ProcessCreationResult
```

API handler 根据 `ProcessLaunchOutcome` 映射返回值和写出
`PROCESS_INFORMATION`，但不能修改其中的 request 或 decision。

### 5.11 Loaded image 和运行上下文

```python
@dataclass(frozen=True)
class LoadedChildImage:
    request_launch_id: str
    module: EmulatedModuleProtocol
    image_base: int
    entrypoint_address: int
    primary: Literal[False] = False


@dataclass
class ChildProcessContext:
    process: EmulatedProcessProtocol
    thread: EmulatedThreadProtocol
    module: EmulatedModuleProtocol
    run: EmulatedRunProtocol
    ownership: ChildEventOwnership
```

### 5.12 ChildRunResult

```python
@dataclass(frozen=True)
class ChildRunResult:
    launch_id: str
    ownership: ChildEventOwnership
    state: ChildExecutionState
    outcome: ChildOutcome
    termination_reason: ChildTerminationReason
    budget: ExecutionBudget
    usage: BudgetUsage
    run_indexes: tuple[int, ...]
    error: ChildFailure | None
```

### 5.13 Failure 和 parent snapshots

```python
@dataclass(frozen=True)
class ChildFailure:
    kind: ChildFailureKind
    message: str
    pc: int | None = None
    api_name: str | None = None


@dataclass(frozen=True)
class ParentExecutionSnapshot:
    root_sample_sha256: str
    pid: int
    tid: int | None
    cwd: str
    budget: ExecutionBudget


@dataclass(frozen=True)
class ParentRunOutcome:
    status: str
    termination_reason: str
    coverage_complete: bool
    budget: ExecutionBudget
    usage: BudgetUsage
```

`ChildExecutionReportData` 是实现层 DTO；对 dynamic stage 暴露时转换为现有的
`speakeasy.report.ChildExecutionReport`，不能把 engine 对象放进报告。

### 5.14 Ownership

```python
@dataclass(frozen=True)
class ChildEventOwnership:
    root_sample_sha256: str
    launch_id: str
    parent_pid: int
    child_pid: int
    depth: int
```

事件自身的 `pos.pid` 仍表示执行事件时的活动进程；ownership 只是不可覆盖的
关联上下文。

### 5.15 ChildExecutionReportData

```python
@dataclass(frozen=True)
class ChildExecutionReportData:
    mode: str
    execution_enabled: bool
    request_count: int
    eligible_count: int
    target_resolved_count: int
    process_object_created_count: int
    thread_queued_count: int
    entrypoint_reached_count: int
    records: tuple[ChildLaunchRecord, ...]
    results: tuple[ChildRunResult, ...]
```

该对象是 engine 内部不可变快照；序列化时由 reporting 转换为
`speakeasy.report.ChildExecutionReport`。

## 6. 模块接口

接口定义放在 `interfaces.py`，实现类不得向其他模块暴露私有属性。所有公共方法
必须有类型标注和 docstring。

### 6.1 RequestFactory

```python
class ChildRequestFactory(Protocol):
    def build(
        self,
        spec: ProcessLaunchSpec,
        *,
        root_sample_sha256: str,
        parent_pid: int,
        parent_tid: int | None,
        parent_launch_id: str | None,
        depth: int,
        parent_budget: ExecutionBudget,
        cwd: str,
    ) -> ChildLaunchRequest:
        """Create a stable request without resolving or executing the target."""
```

### 6.2 TargetResolver

```python
class ChildTargetResolverProtocol(Protocol):
    def resolve(self, request: ChildLaunchRequest) -> ResolvedChildTarget:
        """Resolve target bytes only from self/dropped/fixture sources."""

    def register_fixture(self, normalized_path: str, data: bytes) -> None:
        """Register exact emulation bytes for an explicitly allowed path."""
```

### 6.3 AdmissionPolicy

```python
class ChildAdmissionPolicyProtocol(Protocol):
    def evaluate(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
        *,
        launch_history: Sequence[ChildLaunchRecord],
    ) -> AdmissionDecision:
        """Return an admission decision without mutating scheduler or engine state."""
```

### 6.4 BudgetFactory

```python
class ParentRuntimeConfig(Protocol):
    timeout: float
    max_api_count: int
    max_instructions: int


class ChildBudgetFactory(Protocol):
    def capture_parent(self, config: ParentRuntimeConfig) -> ExecutionBudget:
        """Capture the immutable parent limit values once at root start."""

    def for_child(
        self,
        parent_budget: ExecutionBudget,
    ) -> tuple[ExecutionBudget, BudgetUsage]:
        """Return equal child limits and a fresh usage counter."""

    def observe_api(self, usage: BudgetUsage) -> None:
        """Increment exactly one active child usage counter."""

    def observe_instructions(self, usage: BudgetUsage, count: int = 1) -> None:
        """Increment exactly one active child usage counter."""

    def exceeded(self, budget: ExecutionBudget, usage: BudgetUsage) -> str | None:
        """Return the exceeded limit name, or None."""
```

这里的 `observe_*` 只能由 runner/hook 调用；handler 和 detector 不得写 usage。

### 6.5 ProcessObjectFactory

```python
class ChildProcessFactory(Protocol):
    def create(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
    ) -> ProcessCreationResult:
        """Create the emulated Process/Thread objects for one admitted launch."""
```

`ProcessCreationResult` 必须明确包含 `process`、`created_pid`、`created_tid` 和
失败原因。创建 Process 对象不等于 child 已执行。

### 6.6 RuntimeLoader 和 ContextManager

```python
class ChildRuntimeLoader(Protocol):
    def load(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
    ) -> LoadedChildImage:
        """Load child bytes with primary=False and preserve root metadata."""


class ChildContextManager(Protocol):
    def enter(
        self,
        request: ChildLaunchRequest,
        image: LoadedChildImage,
        ownership: ChildEventOwnership,
    ) -> ContextManager[ChildProcessContext]:
        """Create/switch child context and restore parent context on exit."""
```

`ChildContextManager.enter()` 必须是上下文管理器；异常路径也必须恢复 parent。

### 6.7 Scheduler

```python
class ChildSchedulerProtocol(Protocol):
    def submit(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
        decision: AdmissionDecision,
        process: EmulatedProcessProtocol,
    ) -> ChildLaunchRecord:
        """Record an admitted request; never execute it here."""

    def drain(self, parent_result: ParentRunOutcome) -> tuple[ChildRunResult, ...]:
        """Run queued children only after the parent has finished its runs."""

    def stop(self, reason: str) -> None:
        """Stop pending and active children with a scheduler-level reason."""

    def snapshot(self) -> ChildExecutionReportData:
        """Return an immutable report snapshot without exposing queue internals."""
```

### 6.8 EntrypointObserver 和 Runner

```python
class ChildEntrypointObserver(Protocol):
    def arm(self, context: ChildProcessContext) -> None:
        """Install a one-shot entrypoint observation hook."""

    def reached(self, launch_id: str) -> bool:
        """Return whether the hook actually fired."""


class ChildRunnerProtocol(Protocol):
    def run(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
        image: LoadedChildImage,
        context: ChildProcessContext,
        budget: ExecutionBudget,
        usage: BudgetUsage,
    ) -> ChildRunResult:
        """Queue, execute and finalize exactly one child run."""
```

runner 必须同时设置 `thread_queued=true` 和之后的 `entrypoint_reached=true`；
不能由一个推断另一个。

### 6.9 ResultSink 和 Dynamic Adapter

```python
class ChildResultSink(Protocol):
    def publish(self, result: ChildRunResult) -> None:
        """Attach one child result to the root report."""


class DynamicChildResultAdapter(Protocol):
    def apply(
        self,
        tracker: ProcessExecutionTracker,
        report: ChildExecutionReport,
    ) -> None:
        """Consume authoritative launch/result fields without inventing state."""
```

dynamic adapter 只能读取报告的公共 DTO，不能访问 engine、Process 内部对象或
scheduler 私有队列。

### 6.10 Dispatcher

```python
class ChildExecutionDispatcher(Protocol):
    def submit(
        self,
        spec: ProcessLaunchSpec,
        *,
        parent_context: ParentExecutionSnapshot,
    ) -> ProcessLaunchOutcome:
        """Create/resolve/admit one request and optionally enqueue it."""

    def parent_finished(self, parent_result: ParentRunOutcome) -> None:
        """Close parent request intake and start the bounded child drain."""

    def stop(self, reason: str) -> None:
        """Propagate a lifecycle stop to pending and active child work."""

    def report(self) -> ChildExecutionReportData:
        """Return the model-only or executed child report summary."""
```

`submit()` 的 model-only 模式只能记录；只有 `options.enabled=true` 且
admission 成功时，才允许创建 queued record。

## 7. 公共调用接口

### 7.1 WindowsEmulator

`WindowsEmulator` 只暴露一个 process-launch facade：

```python
def request_process_execution(
    self,
    spec: ProcessLaunchSpec,
    *,
    parent_context: ParentExecutionSnapshot | None = None,
) -> ProcessLaunchOutcome:
    """Record a launch request and apply the configured child policy."""
```

旧的 `request_child_process(...)` 可以在迁移期保留为兼容包装，但必须调用这个
facade，不允许复制编排逻辑。

### 7.2 Win32Emulator

执行入口在迁移期保持向后兼容，但最终必须通过显式 options 启用：

```python
def run_module(
    self,
    module: EmulatedModuleProtocol,
    all_entrypoints: bool = False,
    entry_point: int | None = None,
    *,
    child_execution: ChildExecutionOptions | None = None,
) -> None:
    """Run the root module and, only if explicitly enabled, drain child work."""
```

兼容规则：

- `emulate_children=False` 或 options 缺失：只记录 request，不执行 child；
- `emulate_children=True`：迁移期映射为显式 options，但在 scheduler/D 工作包
  完成前仍不得执行；
- 不允许 handler 或 CLI 直接修改 `child_execution.enabled` 属性。

### 7.3 Speakeasy 和 CLI

高层包装和 CLI 应传递同一个 `ChildExecutionOptions`：

```python
def run_module(
    self,
    module: EmulatedModuleProtocol,
    all_entrypoints: bool = False,
    emulate_children: bool = False,
    entry_point: int | None = None,
    *,
    child_execution: ChildExecutionOptions | None = None,
) -> None:
    """Forward the declared child policy to the engine."""
```

CLI 只负责构造 options，不解析 launch、不生成 pid、不访问 runner。

## 8. 调度时序

```text
root API handler
  -> request_process_execution(spec)
       -> request factory
       -> target resolver
       -> admission policy
       -> process object factory
       -> scheduler.submit()
  -> returns mapped API result

parent run queue completes
  -> dispatcher.parent_finished()
       -> scheduler.drain()
            -> runtime.loader
            -> context.enter()
            -> observer.arm()
            -> runner.run()
            -> reporting.publish()
            -> context.__exit__()
  -> dispatcher.report()
  -> dynamic adapter
```

调度器在 drain 期间必须保持 FIFO。child 在入口处再次提交 launch 时，dispatcher
记录 request，但 depth policy 拒绝其执行，避免递归。

## 9. 错误和状态所有权

| 事实 | 唯一写入者 | 主要输出 |
|---|---|---|
| `requested` | request factory | request record |
| `target_resolved` | target resolver | resolution evidence |
| `eligible` | admission policy | admission decision |
| `process_object_created` | process object factory | pid/tid |
| `thread_queued` | scheduler | queue transition |
| `entrypoint_reached` | runner/observer | one-shot hook evidence |
| `completed/partial/failed` | runner | result |
| parent outcome | existing root pipeline | parent status |
| child report | reporting | child summary |

任何模块不得写不属于自己的状态字段。child 的预期失败由 dispatcher/runner 转成
`ChildFailure`；不得冒泡成 parent simulation error。只有 scheduler 自身无法维持
状态一致性时才允许上报 engine-level internal error，并必须保留已完成 child 的
报告。

## 10. 预算实现细则

### 10.1 父子同额

root 开始时调用：

```python
parent_budget = budget_factory.capture_parent(parent_config)
```

每个 child 调用：

```python
child_budget, child_usage = budget_factory.for_child(parent_budget)
```

`for_child()` 只在 `source` 字段上标为 `parent_config`，其余三个 limit 与 parent
逐项相等。不能使用 5 秒、1,000 API 或 1,000,000 指令作为 child 隐藏上限。

### 10.2 计数边界

- `observe_api()` 由 API-dispatch hook 对当前 active child 调用一次；
- `observe_instructions()` 由 instruction hook 对当前 active child 更新；
- timeout 由 runner 使用注入的 clock 计算；
- parent 和 sibling child 的 `BudgetUsage` 不共享引用；
- `budget.exceeded()` 只产生 child termination reason；
- 预算耗尽后 runner 停止 child run queue，不继续启动 grandchild。

### 10.3 配置值为 -1

若 parent 的 `max_instructions=-1`，child 仍为 `-1`。若上层流水线不接受无限
instruction budget，必须在构造 parent config 时显式修改；不能在 child runner
中静默替换。

## 11. 报告接口

顶层报告保持：

```text
Report.child_execution
  mode
  execution_enabled
  request_count
  eligible_count
  target_resolved_count
  process_object_created_count
  thread_queued_count
  entrypoint_reached_count
  states
  requests[]
```

执行阶段增加：

```text
results[]
  launch_id
  ownership
  outcome
  termination_reason
  budget_source
  budget_limits
  budget_usage
  run_indexes
  failure
```

child 实际 Run 继续进入 `Report.entry_points`，由 ownership 关联；不得为 child
复制一套 API/file/network 数据结构。

## 12. Dynamic stage 接口

`src/dynamic_stage_new` 只依赖报告 DTO：

```python
class ChildExecutionReportConsumer(Protocol):
    def consume(self, report: ChildExecutionReport) -> None:
        """Apply engine-produced child launch/result state to the tracker."""
```

字段映射规则：

| tracker 字段 | 权威来源 |
|---|---|
| `launch_id` | engine `ChildLaunchRequest.launch_id` |
| `process_object_created` | process factory result |
| `child_pid` | process factory result |
| `child_started` | `entrypoint_reached` |
| `child_emulated` | child result `completed/partial/error` |
| `coverage` | child result coverage |
| `termination_reason` | child result |

tracker 不得从 API result、Process 是否存在或后续任意 pid 事件反推这些字段。

## 13. 迁移顺序

### 步骤 1：接口冻结

- [x] 评审本文的 DTO、Protocol 和 owner；
- [x] 确定公共符号兼容列表；
- [x] 不修改 engine 行为；
- [x] 将纯声明合同放在 `speakeasy/windows/child_execution_contracts/`，
      避免与当前 `speakeasy/windows/child_execution.py` 单文件形成同名
      module/package 冲突；
- [x] `models.py`、`interfaces.py` 和 `__init__.py` 只导出冻结声明；
- [x] 使用 `tests/test_child_execution_contracts.py` 固化预算等额、
      usage 独立、frozen DTO 和显式 fake 注入约束；
- [x] 步骤 2 package 化时，再把该合同层迁入稳定的
      `child_execution` package 公共导入路径。

### 步骤 2：package 化重构

- [x] 将当前单文件拆到 `models.py`、`interfaces.py`、`request.py`、
      `targets.py`、`policy.py` 和 `registry.py`；
- [x] `__init__.py` 继续导出 `ChildExecutionPolicy`、
      `ChildExecutionRegistry`、`ChildExecutionRequest`、
      `ChildExecutionState`、`ChildTargetResolver` 和
      `ChildTargetSource`；
- [x] 将冻结合同从 `child_execution_contracts/` 迁入稳定
      `child_execution` package；迁移完成后删除 staging 目录；
- [x] 迁移现有 model-only 和 contract 测试到稳定 package 路径；
- [x] registry 通过构造参数接受 `policy`、`resolver` 和
      `request_factory`，不通过 monkey patch 或动态属性注入扩展；
- [x] 所有新增公共接口均有类型标注和 docstring，明确 args、returns、
      side effects 和状态所有权；
- [x] 删除旧 `child_execution.py` 单文件，但保持公共 import 行为；
- [x] 不增加 child execution、run queue、environment-variable switch 或
      `ENV_ENABLE=1` 一类传参；
- [x] child-execution 定向测试和 contract 测试：通过；
- [x] Ruff：通过；
- [x] 全量测试：`366 passed, 26 skipped, 5 failed`；5 个失败是既有缺失
      `tests/capa-testfiles` 资产和既有引擎行为差异，与本次 package
      切换无关。

### 步骤 3：budget 和 dispatcher

- [x] 实现冻结的 `ExecutionBudget`、具体
      `ExecutionBudgetFactory` 和 `ChildLaunchDispatcher`；
- [x] parent snapshot 与每个 child 的三项限额逐项相同；
- [x] parent、child、sibling 的 `BudgetUsage` 不共享引用；
- [x] dispatcher 通过构造参数显式注入 request factory、target resolver、
      admission policy、process factory、scheduler 和 options；
- [x] disabled/model-only 只记录 request 和 process-object 事实，不调用
      scheduler；
- [x] enabled 时仅 eligible 且 process object 创建成功的 request 才委托
      scheduler；
- [x] `parent_finished()` 永久关闭 intake；失败 parent 传播 stop，成功 parent
      只通过 scheduler 的公共接口 drain；
- [x] report 返回由 dispatcher 自己持有的不可变快照，不暴露内部列表；
- [x] 用显式 fake resolver/policy/process factory/scheduler 做单元及集成测试；
- [x] 仍不加入 child run queue、loader、context manager、entry hook 或 runner；
- [x] 生产实现没有环境变量传参、`ENV_ENABLE=1`、monkey patch、动态属性注入
      或私有字段穿透；
- [x] 公共类和公共方法均有类型标注及 Args/Returns/Side effects 注释；
- [x] child-execution 阶段 3 新增预算、dispatcher 和集成测试：通过；
- [x] 阶段 3 与既有 child-execution 回归合计：`68 passed`；
- [x] 阶段 3 文件 Ruff 与 `py_compile`：通过。
- [x] 全量测试：`398 passed, 26 skipped, 5 failed`；失败仍是缺失
      `tests/capa-testfiles` 资产及既有引擎行为差异，与阶段 3 无关。

### 步骤 4：loader/context/runner

- [x] 实现 `runtime_loader.py` 的 `ChildImageRuntimeLoader`；
- [x] child target 在物化前校验 resolved、PE、EXE、size、SHA-256 和入口点；
- [x] `PeChildImageMaterializer` 直接使用已解析字节构建 `LoadedImage`，不调用
      高层 `load_module()`；
- [x] `EngineChildImageBaseAllocator` 通过公共地址范围接口选择 child base，
      避免与 root image 的 preferred base 冲突；
- [x] `EngineChildImageMapper` 以 `primary=False` 路径映射，并通过公共
      `mem_protect` 恢复 section 权限；
- [x] child loader 不写 root input、root SHA、profiler 静态字符串或 root stack；
- [x] 实现 `runtime_context.py` 的 `ChildRuntimeContextManager`，在正常返回、
      异常返回和 activation 校验失败时都恢复 parent context；
- [x] 实现 `OneShotChildEntrypointObserver`，只通过显式注入的 code-hook
      回调记录 `entrypoint_reached`；
- [x] observer 支持幂等 `disarm()`，runner 在成功、失败和异常路径都会解除
      尚未触发的 hook；
- [x] 实现 `runner.py` 的 `ChildExecutionRunner`，只接受已加载
      non-primary image 和独立 `BudgetUsage`；
- [x] runner 校验 launch ownership、image identity、parent budget 等额和
      usage 类型，预期异常转换为 `ChildRunResult`；
- [x] runner 使用注入的 clock、budget factory、entry observer 和 execution
      backend，不读取环境变量；
- [x] loader/context/runner 均通过显式 Protocol 和构造参数依赖注入；
- [x] 未修改 emulator、API handler、profiler、tracker 或 report 的运行行为；
- [x] 未在实现中使用 `ENV_ENABLE=1`、环境变量传参、monkey patch、动态属性
      注入或私有字段穿透；
- [x] 新增 loader、context、runner 和组合测试，验证 root metadata 哨兵不变、
      parent context 恢复、one-shot 入口证据和 child 预算独立；
- [x] 步骤 4 定向测试：`33 passed`；
- [x] 全部 child-execution 回归：`101 passed`；
- [x] 阶段 4 文件 Ruff、包导出检查和 `py_compile`：通过；
- [x] 全量测试：`431 passed, 26 skipped, 5 failed`；5 个失败仍是既有缺失
      `tests/capa-testfiles` 资产及既有引擎行为差异，与步骤 4 无关；
- [ ] 真实 emulator/scheduler 在 `mira` fixture 上的端到端接入；调度器尚未
      实现，因此本步骤只冻结并验证 loader/context/runner 接口和独立实现；
- [ ] 真实 child run 的 end-to-end parent metadata/report 验收，留到
      scheduler、report/dynamic adapter 接入后执行。

### 步骤 5：report/dynamic adapter

- 增加 child result 和 ownership；
- 让 tracker 消费权威报告；
- 移除基于 API result 和 pid 活动的推断。

### 步骤 6：小批实验

- `mira` self + depth=1；
- 完整 dropped EXE；
- `padodor` unavailable；
- `systex` 不执行 IE；
- R3 良性安装器噪声检查；
- 最后才评估 depth=2。

## 14. 接口验收清单

- [ ] 每个模块都有单一职责和明确依赖方向。
- [ ] 所有公共接口有类型标注和 docstring。
- [ ] dispatcher 是唯一状态编排入口。
- [ ] API handler 不直接调用 runner/loader。
- [ ] child budget 三项与 parent 逐项相同。
- [ ] parent 和 child 使用独立 usage 计数。
- [x] child loader 使用 `primary=False`，不覆盖 root metadata。
- [ ] scheduler 在 parent 完成前不 drain。
- [x] runner 的入口 hook 是 `entrypoint_reached` 唯一证据。
- [ ] child result 有稳定 ownership 并可回溯 run index。
- [ ] dynamic adapter 只消费报告 DTO。
- [ ] 生产代码没有 monkey patch、动态属性注入或私有字段穿透。
- [ ] 测试使用显式 stub/fake、依赖注入和非默认 parent 配置。
