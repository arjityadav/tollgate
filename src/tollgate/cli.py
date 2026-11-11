"""Command line: `tollgate run | approve | deny | pending | verify | scan | pin`."""

import argparse
import json
import sys

import anyio
from mcp import Client, StdioServerParameters
from mcp.server.stdio import stdio_server

from tollgate.approvals import Approvals
from tollgate.audit import verify
from tollgate.config import load_config
from tollgate.gateway import SEP, _list_all, build_gateway
from tollgate.pinning import PinStore
from tollgate.scanner import scan_tool


async def _serve(config_path: str) -> None:
    server = build_gateway(load_config(config_path))
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


async def _inspect(config_path: str, pin: bool) -> None:
    """Connect to every upstream, print findings and pin status; optionally (re)pin clean tools."""
    cfg = load_config(config_path)
    pins = PinStore(cfg.lockfile)
    for name, u in cfg.upstreams.items():
        params = StdioServerParameters(command=u["command"], args=u.get("args", []), env=u.get("env"))
        async with Client(params) as client:
            for tool in await _list_all(client):
                q = f"{name}{SEP}{tool.name}"
                findings = scan_tool(tool)
                status = pins.check(q, tool)
                flag = ", ".join(f"{f.severity}:{f.rule}" for f in findings) or "clean"
                print(f"{q:40} pin={status:8} {flag}")
                if pin and not findings:
                    pins.pin(q, tool)
    if pin:
        print("Pinned all clean tools. Tools with findings were NOT pinned.", file=sys.stderr)


def main() -> None:
    p = argparse.ArgumentParser(prog="tollgate", description="Security gateway for MCP servers")
    p.add_argument("-c", "--config", default="tollgate.yaml")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run", help="serve the gateway over stdio")
    for cmd in ("approve", "deny"):
        sub.add_parser(cmd).add_argument("id")
    sub.add_parser("pending", help="list pending approvals")
    sub.add_parser("verify", help="verify the audit log hash chain")
    sub.add_parser("scan", help="scan upstream tools without serving")
    sub.add_parser("pin", help="accept current definitions of all clean tools")
    a = p.parse_args()

    if a.cmd == "run":
        anyio.run(_serve, a.config)
        return
    cfg = load_config(a.config)
    if a.cmd in ("approve", "deny"):
        approve = a.cmd == "approve"
        ok = Approvals(cfg.approvals_db).decide(a.id, approve)
        print(f"{'approved' if approve else 'denied'} {a.id}" if ok else f"No pending approval {a.id!r} (expired or already decided)")
        sys.exit(0 if ok else 1)
    if a.cmd == "pending":
        for approval_id, tool, args in Approvals(cfg.approvals_db).pending():
            print(f"{approval_id}  {tool}  {json.dumps(json.loads(args))}")
    elif a.cmd == "verify":
        ok, _, msg = verify(cfg.audit_log)
        print(("OK: " if ok else "TAMPERED: ") + msg)
        sys.exit(0 if ok else 1)
    elif a.cmd in ("scan", "pin"):
        anyio.run(_inspect, a.config, a.cmd == "pin")


if __name__ == "__main__":
    main()
