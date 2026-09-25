"""HTTP 接口（仅标准库）。

端点一览：
  PUT  /v1/tenants/{t}/namespace     注册/更新命名空间视图
  POST /v1/tenants/{t}/policies      发布策略版本（不可覆盖）
  POST /v1/tenants/{t}/evaluate      访问判定
  GET  /v1/decisions/{id}            查询决策：逐步解析链 + 最终命中规则
  POST /v1/tenants/{t}/leases        签发例外租约
  GET  /v1/leases/{id}               查询租约状态与剩余额度
  POST /v1/leases/{id}/revoke        回收租约
  POST /v1/tenants/{t}/replays       对历史决策发起离线回放
  POST /v1/replays/{id}/resume       从中断点续跑回放
  GET  /v1/replays/{id}              查询回放差异报告
  GET  /v1/healthz                   健康检查
"""
from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import errors
from .service import DecisionService, ServiceError


def make_server(service: DecisionService, host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    handler = _build_handler(service)
    return ThreadingHTTPServer((host, port), handler)


def _build_handler(service: DecisionService):
    class Handler(BaseHTTPRequestHandler):
        server_version = "PathPolicy/0.1"
        protocol_version = "HTTP/1.1"

        # ---- 工具 ----

        def _send(self, status: int, payload: dict) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length == 0:
                return {}
            try:
                data = json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                raise ServiceError(errors.INVALID_REQUEST, "请求体不是合法 JSON")
            if not isinstance(data, dict):
                raise ServiceError(errors.INVALID_REQUEST, "请求体必须是 JSON 对象")
            return data

        def log_message(self, fmt, *args):  # 静默访问日志，避免污染审计输出
            return

        # ---- 路由 ----

        def do_GET(self):
            self._route("GET")

        def do_POST(self):
            self._route("POST")

        def do_PUT(self):
            self._route("PUT")

        def _route(self, method: str) -> None:
            try:
                result = self._dispatch(method)
                self._send(200, result)
            except ServiceError as exc:
                self._send(exc.http_status, {"error": exc.code, "message": str(exc)})
            except Exception as exc:  # noqa: BLE001 - 兜底，保证连接不悬挂
                self._send(500, {"error": "INTERNAL", "message": str(exc)})

        def _dispatch(self, method: str) -> dict:
            path = self.path.split("?", 1)[0].rstrip("/") or "/"
            m = re.fullmatch(r"/v1/tenants/([^/]+)/namespace", path)
            if m and method == "PUT":
                return service.put_namespace(self._body())
            m = re.fullmatch(r"/v1/tenants/([^/]+)/policies", path)
            if m and method == "POST":
                body = self._body()
                return service.publish_policy(m.group(1), body.get("version_id", ""), body.get("rules", []),
                                              body.get("published_by", "unknown"))
            m = re.fullmatch(r"/v1/tenants/([^/]+)/evaluate", path)
            if m and method == "POST":
                body = self._body()
                decision = service.evaluate(
                    m.group(1),
                    body.get("path", ""),
                    body.get("operation", ""),
                    body.get("caller_id", ""),
                    tuple(body.get("capabilities", ())),
                    body.get("policy_version"),
                )
                return decision.to_dict()
            m = re.fullmatch(r"/v1/decisions/([^/]+)", path)
            if m and method == "GET":
                return service.get_decision(m.group(1)).to_dict()
            m = re.fullmatch(r"/v1/tenants/([^/]+)/leases", path)
            if m and method == "POST":
                body = self._body()
                lease = service.grant_lease(
                    m.group(1),
                    body.get("approved_by", ""),
                    body.get("paths", []),
                    body.get("operations", []),
                    int(body.get("max_uses", 0)),
                    int(body.get("ttl_seconds", 0)),
                )
                return lease.to_dict(service._clock())
            m = re.fullmatch(r"/v1/leases/([^/]+)", path)
            if m and method == "GET":
                return service.get_lease(m.group(1)).to_dict(service._clock())
            m = re.fullmatch(r"/v1/leases/([^/]+)/revoke", path)
            if m and method == "POST":
                return service.revoke_lease(m.group(1)).to_dict(service._clock())
            m = re.fullmatch(r"/v1/tenants/([^/]+)/replays", path)
            if m and method == "POST":
                body = self._body()
                return service.start_replay(m.group(1), body.get("policy_version", "")).to_dict()
            m = re.fullmatch(r"/v1/replays/([^/]+)/resume", path)
            if m and method == "POST":
                return service.resume_replay(m.group(1)).to_dict()
            m = re.fullmatch(r"/v1/replays/([^/]+)", path)
            if m and method == "GET":
                return service.get_replay(m.group(1)).to_dict()
            if path == "/v1/healthz" and method == "GET":
                return {"status": "ok"}
            raise ServiceError(errors.INVALID_REQUEST, f"未知路由：{method} {path}", 404)

    return Handler
