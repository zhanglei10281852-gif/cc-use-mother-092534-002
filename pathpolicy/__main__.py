"""服务入口：python3 -m pathpolicy --db data/service.db --port 8080 --approver reviewer-01"""
from __future__ import annotations

import argparse

from .server import make_server
from .service import DecisionService


def main() -> None:
    parser = argparse.ArgumentParser(description="虚拟机敏感路径策略服务")
    parser.add_argument("--db", default="data/service.db", help="SQLite 数据库路径")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--approver", action="append", required=True, help="指定审批人，可重复")
    args = parser.parse_args()

    service = DecisionService(args.db, approvers=set(args.approver))
    server = make_server(service, args.host, args.port)
    print(f"策略服务已启动：http://{args.host}:{args.port}（数据库 {args.db}）")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        service.close()


if __name__ == "__main__":
    main()
