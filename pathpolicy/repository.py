"""SQLite 持久化：只增审计、租约配额、回放游标，全部落盘。

并发安全：进程内所有写操作由一把可重入锁串行化；租约扣减使用
带条件的单条 UPDATE（... WHERE used < quota AND state='active'），
即使绕过锁也无法穿透次数限制。
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from .models import Decision, ExceptionLease, PolicyVersion, Resource, Rule

SCHEMA = """
create table if not exists resources (
    resource_id text not null,
    tenant_id   text not null,
    source      text not null,
    owner_id    text not null,
    labels      text not null default '',
    primary key (tenant_id, resource_id)
);
create table if not exists symlinks (
    tenant_id  text not null,
    link_path  text not null,
    target     text not null,
    primary key (tenant_id, link_path)
);
create table if not exists mounts (
    tenant_id        text not null,
    alias            text not null,
    target           text not null,
    registered_order integer not null,
    shadowed         integer not null default 0,
    primary key (tenant_id, alias, registered_order)
);
create table if not exists policy_versions (
    tenant_id    text not null,
    version      text not null,
    rules_json   text not null,
    published_at text not null,
    published_by text not null,
    base_version text,
    primary key (tenant_id, version)
);
create table if not exists active_policy (
    tenant_id text primary key,
    version   text not null
);
create table if not exists decisions (
    decision_id      text primary key,
    tenant_id        text not null,
    request_id       text unique,
    requested_path   text not null,
    canonical_path   text,
    resource_id      text,
    operation        text not null,
    caller_id        text not null,
    outcome          text not null,
    reason_code      text not null,
    reason_message   text not null,
    policy_version   text,
    rule_id          text,
    lease_id         text,
    resolution_chain text not null,
    rule_trace       text not null,
    request_json     text not null,
    resource_json    text,
    evaluated_at     text not null
);
create table if not exists leases (
    lease_id     text primary key,
    tenant_id    text not null,
    resource_ids text not null,
    operations   text not null,
    quota        integer not null check (quota > 0),
    used         integer not null default 0 check (used <= quota),
    granted_by   text not null,
    granted_at   text not null,
    expires_at   text not null,
    state        text not null check (state in ('active','exhausted','expired','revoked')),
    note         text not null default ''
);
create table if not exists lease_consumptions (
    lease_id    text not null,
    decision_id text not null,
    consumed_at text not null,
    primary key (lease_id, decision_id)
);
create table if not exists event_log (
    event_id    text primary key,
    event_type  text not null,
    aggregate_id text not null,
    tenant_id   text not null,
    payload     text not null,
    occurred_at text not null
);
create table if not exists replay_jobs (
    job_id         text primary key,
    tenant_id      text not null,
    target_version text not null,
    state          text not null check (state in ('running','finished','failed')),
    cursor         text not null default '',
    started_at     text not null,
    finished_at    text,
    scanned        integer not null default 0,
    changed        integer not null default 0
);
create table if not exists replay_diffs (
    job_id       text not null,
    decision_id  text not null,
    evaluated_at text not null,
    requested_path text not null,
    operation    text not null,
    old_outcome  text not null,
    new_outcome  text not null,
    old_rule_id  text,
    new_rule_id  text,
    old_reason   text not null,
    new_reason   text not null,
    primary key (job_id, decision_id)
);
"""


class Repository:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._path = str(path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        if self._path != ":memory:":
            self._conn.execute("pragma journal_mode=WAL")
            self._conn.execute("pragma synchronous=NORMAL")
        self._conn.execute("pragma foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.commit()
            self._conn.close()

    # ---------------------------------------------------------------
    # 命名空间登记
    # ---------------------------------------------------------------
    def upsert_resource(self, resource: Resource) -> None:
        with self._lock:
            row = resource.to_row()
            self._conn.execute(
                "insert into resources(tenant_id, resource_id, source, owner_id, labels) "
                "values(:tenant_id,:resource_id,:source,:owner_id,:labels) "
                "on conflict(tenant_id, resource_id) do update set "
                "source=excluded.source, owner_id=excluded.owner_id, labels=excluded.labels",
                {"tenant_id": resource.tenant_id, **row},
            )
            self._conn.commit()

    def list_resources(self, tenant_id: str) -> dict[str, Resource]:
        with self._lock:
            rows = self._conn.execute(
                "select * from resources where tenant_id=?", (tenant_id,)
            ).fetchall()
        return {r["resource_id"]: Resource.from_row(dict(r)) for r in rows}

    def upsert_symlink(self, tenant_id: str, link_path: str, target: str) -> None:
        with self._lock:
            self._conn.execute(
                "insert into symlinks(tenant_id, link_path, target) values(?,?,?) "
                "on conflict(tenant_id, link_path) do update set target=excluded.target",
                (tenant_id, link_path, target),
            )
            self._conn.commit()

    def list_symlinks(self, tenant_id: str) -> dict[str, str]:
        with self._lock:
            rows = self._conn.execute(
                "select link_path,target from symlinks where tenant_id=?", (tenant_id,)
            ).fetchall()
        return {r["link_path"]: r["target"] for r in rows}

    def add_mount(self, tenant_id: str, alias: str, target: str) -> None:
        """登记挂载并重算覆盖标记。

        后挂载若与先前挂载别名相同，或是先前挂载别名的父前缀，则先前
        挂载被覆盖（shadowed=1）：访问其名下区域时文件身份不可确定。
        """
        with self._lock:
            order_row = self._conn.execute(
                "select coalesce(max(registered_order),0)+1 as next_order from mounts where tenant_id=?",
                (tenant_id,),
            ).fetchone()
            order = order_row["next_order"]
            # 挂载历史只追加：同一别名重复挂载时旧行保留，由 _recompute_mount_shadows
            # 把相关条目标记为身份不可确定
            self._conn.execute(
                "insert into mounts(tenant_id, alias, target, registered_order, shadowed) "
                "values(?,?,?,?,0)",
                (tenant_id, alias, target, order),
            )
            self._recompute_mount_shadows(tenant_id)
            self._conn.commit()

    def _recompute_mount_shadows(self, tenant_id: str) -> None:
        rows = self._conn.execute(
            "select alias, registered_order from mounts where tenant_id=?", (tenant_id,)
        ).fetchall()
        mounts = [(r["alias"], r["registered_order"]) for r in rows]
        for alias, order in mounts:
            shadowed = any(
                # 同一别名被重新挂载：该别名指向过不同目标，身份不可确定
                (other_order != order and other_alias == alias)
                # 后挂载的父前缀覆盖了先挂载的子区域
                or (other_order > order
                    and alias.startswith(other_alias.rstrip("/") + "/"))
                for other_alias, other_order in mounts
            )
            self._conn.execute(
                "update mounts set shadowed=? where tenant_id=? and alias=? "
                "and registered_order=?",
                (1 if shadowed else 0, tenant_id, alias, order),
            )

    def list_mounts(self, tenant_id: str) -> list:
        from .resolver import Mount

        with self._lock:
            rows = self._conn.execute(
                "select alias,target,registered_order,shadowed from mounts "
                "where tenant_id=?",
                (tenant_id,),
            ).fetchall()
        return [
            Mount(
                alias=r["alias"],
                target=r["target"],
                registered_order=r["registered_order"],
                shadowed=bool(r["shadowed"]),
            )
            for r in rows
        ]

    # ---------------------------------------------------------------
    # 策略版本
    # ---------------------------------------------------------------
    def publish_policy(self, policy: PolicyVersion) -> None:
        with self._lock:
            exists = self._conn.execute(
                "select 1 from policy_versions where tenant_id=? and version=?",
                (policy.tenant_id, policy.version),
            ).fetchone()
            if exists:
                raise ValueError(f"策略版本已存在，版本不可覆盖：{policy.version}")
            self._conn.execute(
                "insert into policy_versions(tenant_id,version,rules_json,published_at,"
                "published_by,base_version) values(?,?,?,?,?,?)",
                (
                    policy.tenant_id,
                    policy.version,
                    json.dumps(policy.to_dict()["rules"], ensure_ascii=False),
                    policy.published_at,
                    policy.published_by,
                    policy.base_version,
                ),
            )
            self._conn.execute(
                "insert into active_policy(tenant_id,version) values(?,?) "
                "on conflict(tenant_id) do update set version=excluded.version",
                (policy.tenant_id, policy.version),
            )
            self._conn.commit()

    def get_policy(self, tenant_id: str, version: str) -> PolicyVersion | None:
        with self._lock:
            row = self._conn.execute(
                "select * from policy_versions where tenant_id=? and version=?",
                (tenant_id, version),
            ).fetchone()
        if row is None:
            return None
        return PolicyVersion(
            version=row["version"],
            tenant_id=row["tenant_id"],
            rules=tuple(Rule.from_dict(item) for item in json.loads(row["rules_json"])),
            published_at=row["published_at"],
            published_by=row["published_by"],
            base_version=row["base_version"],
        )

    def active_version(self, tenant_id: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "select version from active_policy where tenant_id=?", (tenant_id,)
            ).fetchone()
        return row["version"] if row else None

    # ---------------------------------------------------------------
    # 审计决定（只增）
    # ---------------------------------------------------------------
    def insert_decision(self, decision: Decision, request_json: str, resource_json: str | None) -> None:
        with self._lock:
            try:
                self._conn.execute(
                    "insert into decisions(decision_id,tenant_id,request_id,requested_path,"
                    "canonical_path,resource_id,operation,caller_id,outcome,reason_code,"
                    "reason_message,policy_version,rule_id,lease_id,resolution_chain,rule_trace,"
                    "request_json,resource_json,evaluated_at) "
                    "values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        decision.decision_id, decision.tenant_id, decision.request_id,
                        decision.requested_path, decision.canonical_path, decision.resource_id,
                        decision.operation, decision.caller_id, decision.outcome,
                        decision.reason_code, decision.reason_message, decision.policy_version,
                        decision.rule_id, decision.lease_id,
                        json.dumps(decision.resolution_chain, ensure_ascii=False),
                        json.dumps(decision.rule_trace, ensure_ascii=False),
                        request_json, resource_json, decision.evaluated_at,
                    ),
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                # 并发的同 request_id 请求已落库：交由上层回查既有决定
                self._conn.rollback()
                raise

    def find_decision_by_request(self, request_id: str) -> Decision | None:
        with self._lock:
            row = self._conn.execute(
                "select * from decisions where request_id=?", (request_id,)
            ).fetchone()
        return self._row_to_decision(row) if row else None

    def get_decision(self, decision_id: str) -> Decision | None:
        with self._lock:
            row = self._conn.execute(
                "select * from decisions where decision_id=?", (decision_id,)
            ).fetchone()
        return self._row_to_decision(row) if row else None

    def get_decision_facts(self, decision_id: str) -> tuple[dict, dict | None] | None:
        with self._lock:
            row = self._conn.execute(
                "select request_json,resource_json from decisions where decision_id=?",
                (decision_id,),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["request_json"]), (
            json.loads(row["resource_json"]) if row["resource_json"] else None
        )

    def iter_decisions(
        self, tenant_id: str, after_iso: str, after_id: str, limit: int
    ) -> list[sqlite3.Row]:
        """按 (evaluated_at, decision_id) 顺序翻页，游标为复合键的上一行值。"""
        with self._lock:
            if after_iso:
                return list(self._conn.execute(
                    "select * from decisions where tenant_id=? "
                    "and (evaluated_at, decision_id) > (?, ?) "
                    "order by evaluated_at, decision_id limit ?",
                    (tenant_id, after_iso, after_id, limit),
                ).fetchall())
            return list(self._conn.execute(
                "select * from decisions where tenant_id=? "
                "order by evaluated_at, decision_id limit ?",
                (tenant_id, limit),
            ).fetchall())

    @staticmethod
    def _row_to_decision(row: sqlite3.Row) -> Decision:
        return Decision(
            decision_id=row["decision_id"],
            tenant_id=row["tenant_id"],
            request_id=row["request_id"],
            requested_path=row["requested_path"],
            canonical_path=row["canonical_path"],
            resource_id=row["resource_id"],
            operation=row["operation"],
            caller_id=row["caller_id"],
            outcome=row["outcome"],
            reason_code=row["reason_code"],
            reason_message=row["reason_message"],
            policy_version=row["policy_version"],
            rule_id=row["rule_id"],
            lease_id=row["lease_id"],
            resolution_chain=tuple(json.loads(row["resolution_chain"])),
            rule_trace=tuple(json.loads(row["rule_trace"])),
            evaluated_at=row["evaluated_at"],
        )

    # ---------------------------------------------------------------
    # 例外租约
    # ---------------------------------------------------------------
    def insert_lease(self, lease: ExceptionLease) -> None:
        with self._lock:
            row = lease.to_row()
            self._conn.execute(
                "insert into leases(lease_id,tenant_id,resource_ids,operations,quota,used,"
                "granted_by,granted_at,expires_at,state,note) "
                "values(:lease_id,:tenant_id,:resource_ids,:operations,:quota,:used,"
                ":granted_by,:granted_at,:expires_at,:state,:note)",
                row,
            )
            self._conn.commit()

    def list_active_leases(self, tenant_id: str) -> list[ExceptionLease]:
        with self._lock:
            rows = self._conn.execute(
                "select * from leases where tenant_id=? and state='active'", (tenant_id,)
            ).fetchall()
        return [ExceptionLease.from_row(dict(r)) for r in rows]

    def list_leases(self, tenant_id: str) -> list[ExceptionLease]:
        with self._lock:
            rows = self._conn.execute(
                "select * from leases where tenant_id=?", (tenant_id,)
            ).fetchall()
        return [ExceptionLease.from_row(dict(r)) for r in rows]

    def get_lease(self, lease_id: str) -> ExceptionLease | None:
        with self._lock:
            row = self._conn.execute(
                "select * from leases where lease_id=?", (lease_id,)
            ).fetchone()
        return ExceptionLease.from_row(dict(row)) if row else None

    def mark_lease_state(self, lease_id: str, state: str) -> None:
        with self._lock:
            self._conn.execute(
                "update leases set state=? where lease_id=? and state='active'",
                (state, lease_id),
            )
            self._conn.commit()

    def try_consume_lease(self, lease_id: str, now_iso: str) -> bool:
        """原子扣减一次额度。

        条件 UPDATE 在 SQLite 写锁内完成：只有 used<quota 的活动租约
        能把行改掉，并发调用者最多有 quota 个看到 rowcount=1。
        """
        with self._lock:
            cursor = self._conn.execute(
                "update leases set used=used+1, "
                "state=case when used+1>=quota then 'exhausted' else state end "
                "where lease_id=? and state='active' and used<quota and expires_at>?",
                (lease_id, now_iso),
            )
            consumed = cursor.rowcount == 1
            self._conn.commit()
            return consumed

    def refund_lease(self, lease_id: str) -> None:
        """扣减后决定未能落库（幂等竞态）时归还一次额度。"""
        with self._lock:
            self._conn.execute(
                "update leases set used=max(0,used-1), "
                "state=case when state='exhausted' then 'active' else state end "
                "where lease_id=?",
                (lease_id,),
            )
            self._conn.commit()

    def record_consumption(self, lease_id: str, decision_id: str, now_iso: str) -> None:
        with self._lock:
            self._conn.execute(
                "insert or ignore into lease_consumptions(lease_id,decision_id,consumed_at) "
                "values(?,?,?)",
                (lease_id, decision_id, now_iso),
            )
            self._conn.commit()

    def expire_due_leases(self, now_iso: str) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "select lease_id from leases where state='active' and expires_at<=?",
                (now_iso,),
            ).fetchall()
            ids = [r["lease_id"] for r in rows]
            self._conn.execute(
                "update leases set state='expired' where state='active' and expires_at<=?",
                (now_iso,),
            )
            self._conn.commit()
        return ids

    # ---------------------------------------------------------------
    # 事件日志
    # ---------------------------------------------------------------
    def append_event(
        self, event_id: str, event_type: str, aggregate_id: str,
        tenant_id: str, payload: dict, now_iso: str,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "insert into event_log(event_id,event_type,aggregate_id,tenant_id,payload,occurred_at) "
                "values(?,?,?,?,?,?)",
                (event_id, event_type, aggregate_id, tenant_id,
                 json.dumps(payload, ensure_ascii=False), now_iso),
            )
            self._conn.commit()

    # ---------------------------------------------------------------
    # 回放作业与差异（原审计表 decisions 永不变更）
    # ---------------------------------------------------------------
    def insert_replay_job(self, job) -> None:
        with self._lock:
            self._conn.execute(
                "insert into replay_jobs(job_id,tenant_id,target_version,state,cursor,"
                "started_at,scanned,changed) values(?,?,?,?,?,?,0,0)",
                (job.job_id, job.tenant_id, job.target_version, job.state,
                 job.cursor, job.started_at),
            )
            self._conn.commit()

    def get_replay_job(self, job_id: str):
        from .models import ReplayJob

        with self._lock:
            row = self._conn.execute(
                "select * from replay_jobs where job_id=?", (job_id,)
            ).fetchone()
        if row is None:
            return None
        return ReplayJob(
            job_id=row["job_id"], tenant_id=row["tenant_id"],
            target_version=row["target_version"], state=row["state"],
            cursor=row["cursor"], started_at=row["started_at"],
            finished_at=row["finished_at"], scanned=row["scanned"],
            changed=row["changed"],
        )

    def save_replay_progress(
        self, job_id: str, cursor: str, scanned: int, changed: int,
        state: str, finished_at: str | None = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "update replay_jobs set cursor=?, scanned=?, changed=?, state=?, finished_at=? "
                "where job_id=?",
                (cursor, scanned, changed, state, finished_at, job_id),
            )
            self._conn.commit()

    def insert_replay_diff(self, diff) -> None:
        with self._lock:
            self._conn.execute(
                "insert or ignore into replay_diffs(job_id,decision_id,evaluated_at,"
                "requested_path,operation,old_outcome,new_outcome,old_rule_id,new_rule_id,"
                "old_reason,new_reason) values(?,?,?,?,?,?,?,?,?,?,?)",
                (diff.job_id, diff.decision_id, diff.evaluated_at, diff.requested_path,
                 diff.operation, diff.old_outcome, diff.new_outcome, diff.old_rule_id,
                 diff.new_rule_id, diff.old_reason, diff.new_reason),
            )
            self._conn.commit()

    def list_replay_diffs(self, job_id: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "select * from replay_diffs where job_id=? order by evaluated_at, decision_id",
                (job_id,),
            ).fetchall()
        return [dict(r) for r in rows]
