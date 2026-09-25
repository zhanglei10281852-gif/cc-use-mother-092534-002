# 虚拟机敏感路径策略服务

把规范化路径、文件来源、所有者、敏感标签、调用能力与操作类型合并为可版本化
允许/拒绝决定的文件命名空间判定服务。纯 Python 3.11 标准库实现，持久化使用
SQLite，无需外部服务。

## 能力

- **路径解析链**：词法规范化（`.`/`..`、反斜杠）、符号链接逐组件展开（含环
  检测与深度上限）、挂载别名解析、租户根边界校验、压缩包成员名安全校验、
  已登记资源查找；每一步都记录到 `ResolutionStep`，可随决定逐步查询。
- **稳定拒绝原因**：`DENY_LINK_CYCLE`、`DENY_TENANT_ROOT_ESCAPE`、
  `DENY_MOUNT_SHADOWED`、`DENY_UNSAFE_ARCHIVE_MEMBER`、
  `DENY_POLICY_VERSION_MISSING`、`DENY_BY_POLICY`、`DENY_NO_MATCHING_RULE`、
  `DENY_LEASE_EXHAUSTED`、`DENY_LEASE_EXPIRED` 等，代码一经发布不再改名。
- **版本化策略**：规则按操作、来源、敏感标签、所有者、路径 glob、调用能力
  匹配；策略版本只追加不可覆盖，每条决定绑定评估时的版本，并给出全部规则的
  匹配轨迹（最终命中哪条、其余为何跳过）。
- **短期例外租约**：只有指定审批人能签发；绑定精确资源集合与操作集合；
  带额度与到期时间；扣减用条件 UPDATE 完成，并发请求无法穿透次数限制；
  额度耗尽或到期即回收。
- **只增审计**：每个决定落库后不可改写；支持 `request_id` 幂等。
- **策略回放**：新版本发布后对历史访问记录离线重放，只产出差异报告
  （结论翻转或命中规则变化，包括"原本靠租约放行、新策略直接放行"），
  游标按 `(时间, 决定ID)` 复合翻页，进度落盘，可跨重启续跑。

## 目录

- `pathpolicy/`：服务实现
  - `resolver.py`：命名空间解析（规范化、链接、挂载、边界、压缩包成员）
  - `engine.py`：版本化规则引擎与匹配轨迹
  - `models.py`：领域模型
  - `reasons.py`：稳定原因代码
  - `repository.py`：SQLite 持久化（只增审计、租约配额、回放游标）
  - `service.py`：门面服务（判定、签发例外、回放）
  - `clock.py`：可注入时钟
- `domain/`：领域合同、策略代码与事件样例
- `tools/validate_contract.py`：领域资料离线校验
- `tools/demo_service.py`：端到端演示（解析链、租约、回放）
- `tests/`：52 个单元/并发/持久化测试

## 构建与测试

```bash
python3 -m compileall -q .
python3 -m unittest discover -s tests -v
python3 tools/validate_contract.py
python3 tools/demo_service.py
```

所有命令都在项目根目录执行，不需要另行启动数据库、缓存或其他服务。
持久化数据库为单个 SQLite 文件（默认内存模式），传入文件路径即可在重启后
保留资源登记、挂载/链接表、策略版本、决定审计、例外消耗与回放游标。

## 快速示例

```python
from pathpolicy import PathPolicyService, AccessRequest, Rule
from pathpolicy.clock import FakeClock

svc = PathPolicyService("policy.db", clock=FakeClock())
svc.register_resource("t1", "/tenants/t1/secret/key.pem",
                      "tenant_file", "app-svc", frozenset({"secret"}))
svc.publish_policy("t1", "v1", [
    Rule("deny-secret", "deny",
         operations=frozenset({"read"}), labels_any=frozenset({"secret"})),
    Rule("allow-other", "allow"),
], published_by="reviewer-02")

decision = svc.evaluate(AccessRequest(
    tenant_id="t1", requested_path="/tenants/t1/secret/key.pem",
    operation="read", caller_id="job-7",
))
assert decision.outcome == "deny"
print(decision.resolution_chain)  # 逐步解析链
print(decision.rule_trace)        # 每条规则的匹配解释
```
