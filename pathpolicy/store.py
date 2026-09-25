"""SQLite 持久化层。

决策审计 append-only；策略版本不可变；租约消耗与回放游标随写随提交，
进程重启后从数据库完整恢复，不依赖任何内存状态。
"""
from __future__ import annotations

import json
import sqlite3
import threading

from .models import Decision, EvaluationContext, Lease, NamespaceView, PolicyVersion, ReplayJob

SCHEMA = """
CREATE TABLE IF NOT EXISTS namespaces (
    tenant_id   TEXT PRIMARY KEY,
    view        TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_versions (
    tenant_id    TEXT NOT NULL,
    version_id   TEXT NOT NULL,
    payload      TEXT NOT NULL,
    published_by TEXT NOT NULL,
    published_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, version_id)
);
CREATE TABLE IF NOT EXISTS decisions (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id    TEXT NOT NULL UNIQUE,
    tenant_id      TEXT NOT NULL,
    request        TEXT NOT NULL,
    context        TEXT,
    outcome        TEXT NOT NULL,
    reason         TEXT,
    matched_rule   TEXT,
    policy_version TEXT,
    chain          TEXT NOT NULL,
    lease_id       TEXT,
    evaluated_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS leases (
    lease_id    TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    resources   TEXT NOT NULL,
    operations  TEXT NOT NULL,
    max_uses    INTEGER NOT NULL,
    used_count  INTEGER NOT NULL DEFAULT 0,
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS replay_jobs (
    job_id         TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    cursor_seq     INTEGER NOT NULL DEFAULT 0,
    status         TEXT NOT NULL,
    diffs          TEXT NOT NULL DEFAULT '[]',
    scanned        INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL,
    finished_at    TEXT
);
"""


class Store:
    """单连接 SQLite 存储。所有写操作由调用方在服务层锁内执行。"""

    def __init__(self, path: str):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self._write_lock = threading.Lock()

    def close(self) -> None:
        self._conn.close()

    # ---- 命名空间视图 ----

    def save_namespace(self, view: NamespaceView, updated_at: str) -> None:
        with self._write_lock:
            self._conn.execute(
                "INSERT INTO namespaces(tenant_id, view, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(tenant_id) DO UPDATE SET view = excluded.view, updated_at = excluded.updated_at",
                (view.tenant_id, json.dumps(view.to_dict()), updated_at),
            )
            self._conn.commit()

    def get_namespace(self, tenant_id: str) -> NamespaceView | None:
        row = self._conn.execute("SELECT view FROM namespaces WHERE tenant_id = ?", (tenant_id,)).fetchone()
        return NamespaceView.from_dict(json.loads(row["view"])) if row else None

    # ---- 策略版本 ----

    def save_policy(self, policy: PolicyVersion) -> bool:
        """保存新版本；同租户同版本已存在时返回 False（版本不可覆盖）。"""
        with self._write_lock:
            try:
                self._conn.execute(
                    "INSERT INTO policy_versions(tenant_id, version_id, payload, published_by, published_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        policy.tenant_id,
                        policy.version_id,
                        json.dumps(policy.to_dict()),
                        policy.published_by,
                        policy.published_at,
                    ),
                )
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                self._conn.rollback()
                return False

    def get_policy(self, tenant_id: str, version_id: str) -> PolicyVersion | None:
        row = self._conn.execute(
            "SELECT payload FROM policy_versions WHERE tenant_id = ? AND version_id = ?",
            (tenant_id, version_id),
        ).fetchone()
        return PolicyVersion.from_dict(json.loads(row["payload"])) if row else None

    def get_latest_policy(self, tenant_id: str) -> PolicyVersion | None:
        row = self._conn.execute(
            "SELECT payload FROM policy_versions WHERE tenant_id = ? ORDER BY published_at DESC, version_id DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        return PolicyVersion.from_dict(json.loads(row["payload"])) if row else None

    # ---- 访问决策（append-only） ----

    def append_decision(self, decision: Decision) -> Decision:
        with self._write_lock:
            cursor = self._conn.execute(
                "INSERT INTO decisions(decision_id, tenant_id, request, context, outcome, reason, "
                "matched_rule, policy_version, chain, lease_id, evaluated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    decision.decision_id,
                    decision.tenant_id,
                    json.dumps(decision.request),
                    json.dumps(decision.context.to_dict()) if decision.context else None,
                    decision.outcome,
                    decision.reason,
                    decision.matched_rule,
                    decision.policy_version,
                    json.dumps(decision.chain),
                    decision.lease_id,
                    decision.evaluated_at,
                ),
            )
            self._conn.commit()
            decision.seq = cursor.lastrowid
            return decision

    def get_decision(self, decision_id: str) -> Decision | None:
        row = self._conn.execute("SELECT * FROM decisions WHERE decision_id = ?", (decision_id,)).fetchone()
        return _row_to_decision(row) if row else None

    def decisions_after(self, tenant_id: str, cursor_seq: int, limit: int) -> list[Decision]:
        rows = self._conn.execute(
            "SELECT * FROM decisions WHERE tenant_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?",
            (tenant_id, cursor_seq, limit),
        ).fetchall()
        return [_row_to_decision(r) for r in rows]

    # ---- 例外租约 ----

    def save_lease(self, lease: Lease) -> None:
        with self._write_lock:
            self._conn.execute(
                "INSERT INTO leases(lease_id, tenant_id, approved_by, resources, operations, max_uses, "
                "used_count, expires_at, created_at, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    lease.lease_id,
                    lease.tenant_id,
                    lease.approved_by,
                    json.dumps(list(lease.resources)),
                    json.dumps(list(lease.operations)),
                    lease.max_uses,
                    lease.used_count,
                    lease.expires_at,
                    lease.created_at,
                    int(lease.revoked),
                ),
            )
            self._conn.commit()

    def get_lease(self, lease_id: str) -> Lease | None:
        row = self._conn.execute("SELECT * FROM leases WHERE lease_id = ?", (lease_id,)).fetchone()
        return _row_to_lease(row) if row else None

    def leases_for_tenant(self, tenant_id: str) -> list[Lease]:
        rows = self._conn.execute(
            "SELECT * FROM leases WHERE tenant_id = ? AND revoked = 0 AND used_count < max_uses",
            (tenant_id,),
        ).fetchall()
        return [_row_to_lease(r) for r in rows]

    def consume_lease(self, lease_id: str) -> bool:
        """原子消耗一次额度：条件更新保证并发下不会穿透次数限制。"""
        with self._write_lock:
            cursor = self._conn.execute(
                "UPDATE leases SET used_count = used_count + 1 "
                "WHERE lease_id = ? AND used_count < max_uses AND revoked = 0",
                (lease_id,),
            )
            self._conn.commit()
            return cursor.rowcount == 1

    def revoke_lease(self, lease_id: str) -> bool:
        with self._write_lock:
            cursor = self._conn.execute("UPDATE leases SET revoked = 1 WHERE lease_id = ?", (lease_id,))
            self._conn.commit()
            return cursor.rowcount == 1

    # ---- 回放任务 ----

    def save_replay_job(self, job: ReplayJob) -> None:
        with self._write_lock:
            self._conn.execute(
                "INSERT INTO replay_jobs(job_id, tenant_id, policy_version, cursor_seq, status, diffs, "
                "scanned, created_at, finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    job.job_id,
                    job.tenant_id,
                    job.policy_version,
                    job.cursor_seq,
                    job.status,
                    json.dumps(job.diffs),
                    job.scanned,
                    job.created_at,
                    job.finished_at,
                ),
            )
            self._conn.commit()

    def update_replay_job(self, job: ReplayJob) -> None:
        """每批处理后持久化游标与累积差异，重启后可从断点续跑。"""
        with self._write_lock:
            self._conn.execute(
                "UPDATE replay_jobs SET cursor_seq = ?, status = ?, diffs = ?, scanned = ?, finished_at = ? "
                "WHERE job_id = ?",
                (job.cursor_seq, job.status, json.dumps(job.diffs), job.scanned, job.finished_at, job.job_id),
            )
            self._conn.commit()

    def get_replay_job(self, job_id: str) -> ReplayJob | None:
        row = self._conn.execute("SELECT * FROM replay_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if not row:
            return None
        return ReplayJob(
            job_id=row["job_id"],
            tenant_id=row["tenant_id"],
            policy_version=row["policy_version"],
            cursor_seq=row["cursor_seq"],
            status=row["status"],
            diffs=json.loads(row["diffs"]),
            scanned=row["scanned"],
            created_at=row["created_at"],
            finished_at=row["finished_at"],
        )


def _row_to_decision(row: sqlite3.Row) -> Decision:
    return Decision(
        decision_id=row["decision_id"],
        tenant_id=row["tenant_id"],
        request=json.loads(row["request"]),
        context=EvaluationContext.from_dict(json.loads(row["context"])) if row["context"] else None,
        outcome=row["outcome"],
        reason=row["reason"],
        matched_rule=row["matched_rule"],
        policy_version=row["policy_version"],
        chain=json.loads(row["chain"]),
        lease_id=row["lease_id"],
        evaluated_at=row["evaluated_at"],
        seq=row["seq"],
    )


def _row_to_lease(row: sqlite3.Row) -> Lease:
    return Lease(
        lease_id=row["lease_id"],
        tenant_id=row["tenant_id"],
        approved_by=row["approved_by"],
        resources=tuple(json.loads(row["resources"])),
        operations=tuple(json.loads(row["operations"])),
        max_uses=row["max_uses"],
        used_count=row["used_count"],
        expires_at=row["expires_at"],
        created_at=row["created_at"],
        revoked=bool(row["revoked"]),
    )
