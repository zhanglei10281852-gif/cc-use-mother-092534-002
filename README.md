# 虚拟机敏感路径策略服务

文件命名空间判定服务：把同一份文档的各种访问形态（绝对路径、符号链接、挂载别名、
压缩包成员名）规范化为统一路径，结合文件来源、所有者、敏感标签、调用能力与操作
类型给出可版本化的放行/拒绝决策，并支持短期例外租约与历史决策的离线回放。

## 目录

- `pathpolicy/`：服务实现（仅依赖 Python 3.11+ 标准库）
  - `namespace.py`：命名空间解析器，输出规范化路径与逐步解析链
  - `policy.py`：策略版本与规则评估
  - `leases.py`：例外租约（审批人、精确资源集合、额度与到期回收）
  - `replay.py`：离线回放，生成差异报告，不改写原审计
  - `store.py`：SQLite 持久化（决策 append-only，游标与租约消耗随写随提交）
  - `service.py` / `server.py` / `__main__.py`：服务门面、HTTP 接口与入口
- `domain/contract.json`：实体、状态、事件类型和关键业务规则
- `domain/policies.json`：可被程序读取的策略样例
- `examples/`：事件样例、命名空间视图样例、策略版本样例
- `tools/validate_contract.py`：领域资料一致性校验

## 判定语义

**稳定拒绝原因码**（对外契约，语义不变）：

| 原因码 | 含义 |
|---|---|
| `LINK_LOOP` | 符号链接成环或展开次数超限 |
| `TENANT_ROOT_ESCAPE` | 规范化后越过租户根（含压缩包成员越界） |
| `MOUNT_SHADOWED` | 链接目标被更晚的挂载覆盖，无法确定真实对象 |
| `POLICY_VERSION_MISSING` | 请求的策略版本不存在或尚未发布 |
| `NO_MATCHING_RULE` / `RULE_DENIED` | 无规则命中（默认拒绝）/ 显式命中拒绝规则 |
| `APPROVER_NOT_ALLOWED` | 租约签发人不在指定审批人名单 |

**规则评估**：规则按 `(priority, rule_id)` 升序取首个命中；`path_prefix`、`source`、
`owner`、`labels_any`、`capability`、`operations` 各条件为与关系，空字段不限制。
规则拒绝时若存在精确覆盖（规范化路径, 操作）的有效租约，则原子消耗一次额度放行，
决策同时记录被拒绝的规则与租约 id。额度用完、到期或被回收即失效；判定临界区加锁
配合条件更新，并发请求不能穿透次数限制。

**离线回放**：对新策略版本重评估历史决策（重新解析 + 规则评估 + 租约有效性检查，
不消耗租约、不写审计），产出差异报告；每批提交游标，重启后 `resume` 从断点续跑。

## 运行

```bash
python3 -m pathpolicy --db data/service.db --port 8080 --approver reviewer-01
```

主要接口（完整列表见 `pathpolicy/server.py` 模块文档）：

```bash
# 注册命名空间视图与策略版本
curl -X PUT  localhost:8080/v1/tenants/tenant-a/namespace -d @examples/namespace.json
curl -X POST localhost:8080/v1/tenants/tenant-a/policies  -d @examples/policy_v1.json

# 判定：同一文档经符号链接访问，规范化后命中同一条规则
curl -X POST localhost:8080/v1/tenants/tenant-a/evaluate \
  -d '{"path":"/link-to-report","operation":"read","caller_id":"svc-a"}'

# 查询决策：逐步解析链 + 最终命中规则
curl localhost:8080/v1/decisions/<decision_id>

# 签发例外租约（仅指定审批人），查询状态，回收
curl -X POST localhost:8080/v1/tenants/tenant-a/leases \
  -d '{"approved_by":"reviewer-01","paths":["/docs/secret.txt"],"operations":["read"],"max_uses":2,"ttl_seconds":3600}'
curl localhost:8080/v1/leases/<lease_id>
curl -X POST localhost:8080/v1/leases/<lease_id>/revoke

# 策略更新后离线回放，差异报告不改写原审计；中断后可续跑
curl -X POST localhost:8080/v1/tenants/tenant-a/replays -d '{"policy_version":"v2"}'
curl localhost:8080/v1/replays/<job_id>
curl -X POST localhost:8080/v1/replays/<job_id>/resume
```

## 构建与测试

```bash
python3 -m compileall -q .
python3 -m unittest discover -s tests -v
python3 tools/validate_contract.py
```

所有命令都在项目根目录执行；服务数据落盘为单个 SQLite 文件，不需要另行启动
数据库、缓存或其他服务。重启后例外消耗与回放游标从数据库完整恢复。
