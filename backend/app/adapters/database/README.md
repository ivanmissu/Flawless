# 数据库 Adapter 接入

本目录由数据库平台/DBA 团队维护。一个数据库产品一个模块，统一输出 `database` 域资源。

最低证据合同见 `spec.py`：连通性、实例角色、会话、慢 SQL、锁等待、复制、容量、备份和最近变更。恢复不能以“SQL 已提交”为完成，至少重新验证对应故障指标和业务探针。

推荐模块：`mysql.py`、`postgresql.py`、`oracle.py`、`oceanbase.py`、`gaussdb.py`、`tidb.py`、`dameng.py`。凭据只通过 Secret 引用，禁止进入资源事实、证据和异常文本。

## 只读参考 Adapter（阶段 1 样板）

`readonly.py` 提供 `ReadOnlyDatabaseAdapter`，把产品相关的只读传输转换为 `cisre.infrastructure.adapter/v1` 合同（discover / collect_evidence / verify）。它不知道底层是哪种数据库，也不包含任何厂商 SDK、SQL 文本或凭据。

产品团队只需实现 `DatabaseTelemetryClient`：

```python
class MySqlTelemetryClient:
    read_only = True          # 必须显式声明；否则拒绝注册
    provider = "dba-platform"
    engine = "mysql"

    async def list_targets(self) -> list[dict]:
        # 返回 target_id、name、engine、engine_version、role、environment、region、
        # business_service、criticality、endpoint_ref(secret://...)、labels。
        ...

    async def read_section(self, target_id: str, section: str) -> dict:
        # section 只能是 DATABASE_READONLY_SECTIONS 中的名字；只执行固定的只读查询。
        ...
```

注册必须显式调用，导入模块不会产生副作用：

```python
from backend.app.adapters.database import register_database_adapter

register_database_adapter(MySqlTelemetryClient(), adapter_id="database-mysql", section_timeout_seconds=5)
```

### 分区返回约定

| section | 字段 | 用途 |
|---|---|---|
| `connectivity` | `reachable: bool` | 连通性；不可达为 critical |
| `instance_role` | `role` | 主/从/单机 |
| `active_sessions` | `connections_percent`、`active_sessions` | 连接池占用 |
| `slow_queries` | `slow_query_count`、`top_digests` | 只返回指纹，不返回原始 SQL |
| `lock_waits` | `waiting_sessions`、`max_wait_seconds` | 锁等待 |
| `replication` | `replica_count`、`lag_seconds` | 单机时 `replica_count=0` |
| `capacity` | `used_percent` | 空间或表空间使用率 |
| `backup_status` | `last_success_age_hours` | 最近成功备份距今 |
| `recent_changes` | `changes[{at, kind, summary}]` | 最近变更；摘要会脱敏 |
| `business_probe` | `ok: bool` | 验证阶段的业务读写探针 |
| `error_rate` | `ratio_percent` | 验证阶段的错误率 |

### 行为保证

- **只读**：适配器只请求上表中的分区；`verify` 通过同一只读通道重新读取真实目标，不信任执行器回执。
- **部分失败**：单个分区超时、权限不足或异常，只记录为 `collection_errors`，其它分区照常返回；缺失证据时健康度为 `unknown`，绝不报告 `healthy`。
- **fail-closed 验证**：任何判据明确失败即 `recovered=false`；全部通过才 `completed`；缺证据或未知判据为 `unknown`，不会宣布恢复。
- **脱敏**：传输返回中的 password、token、secret、credential、dsn 等字段会被删除并记录数量；错误文本中的连接串整体替换为 `<redacted-url>`。
- **端点引用**：`endpoint_ref` 必须以 `secret://` 开头，包含明文连接串的目标会被拒绝。
- **超时**：每个分区都有截止时间（默认 5 秒，最长 60 秒）。

### 阈值（默认值，产品团队可在自己的 Adapter 中按产品调整）

| 指标 | 降级 | 严重 | 恢复判据 |
|---|---|---|---|
| 连接占用 | ≥ 85% | ≥ 95% | — |
| 复制延迟 | ≥ 30s | ≥ 120s | ≤ 30s（有从库时） |
| 锁等待 | 任一等待会话或最长等待 ≥ 30s | ≥ 50 个等待会话或最长等待 ≥ 60s | 无等待会话 |
| 容量 | ≥ 85% | ≥ 95% | — |
| 备份距今 | ≥ 24h | ≥ 72h | — |
| 慢 SQL 数量 | ≥ 10 | ≥ 100 | — |
| 错误率 | — | — | ≤ 1% |

### 下一步（数据库团队）

1. 在本目录新增 `mysql.py` / `postgresql.py` 等产品模块，实现 `DatabaseTelemetryClient`；只使用固定只读查询（如 `performance_schema`、`information_schema`、复制状态视图）。
2. 为每个产品补充合同测试：成功、超时、权限拒绝、上游 5xx、脱敏和“单机无从库”场景。
3. 编写 3 个高频只读 Skill（连接耗尽、复制延迟、锁等待），动作只能使用 `db_*` 动作 ID 并逐项审批。
