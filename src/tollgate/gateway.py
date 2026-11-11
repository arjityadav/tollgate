"""Tollgate: an MCP server that fronts other MCP servers. Step 2: a transparent proxy."""

from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from mcp import Client
from mcp.server import Server, ServerRequestContext
from mcp.types import (
    CallToolRequestParams, CallToolResult, ListToolsResult,
    PaginatedRequestParams, TextContent, Tool,
)

SEP = "__"  # qualified name = "<upstream>__<tool>"


@dataclass
class State:
    clients: dict[str, Client] = field(default_factory=dict)
    tools: dict[str, tuple[str, Tool]] = field(default_factory=dict)  # qualified -> (upstream, tool)


def error(text: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=True)


async def _list_all(client: Client) -> list[Tool]:
    tools, cursor = [], None
    while True:
        page = await client.list_tools(cursor=cursor)
        tools.extend(page.tools)
        if not (cursor := page.next_cursor):
            return tools


def build_gateway(targets: dict[str, Any]) -> Server[State]:
    """`targets` maps an upstream name to anything mcp.Client accepts."""

    @asynccontextmanager
    async def lifespan(_: Server[State]) -> AsyncIterator[State]:
        state = State()
        async with AsyncExitStack() as stack:  # keeps every upstream connection open
            for name, target in targets.items():
                client = await stack.enter_async_context(Client(target))
                state.clients[name] = client
                for tool in await _list_all(client):
                    state.tools[f"{name}{SEP}{tool.name}"] = (name, tool)
            yield state

    async def list_tools(ctx: ServerRequestContext[State], params: PaginatedRequestParams | None) -> ListToolsResult:
        state = ctx.lifespan_context
        return ListToolsResult(tools=[t.model_copy(update={"name": q}) for q, (_, t) in state.tools.items()])

    async def call_tool(ctx: ServerRequestContext[State], params: CallToolRequestParams) -> CallToolResult:
        state = ctx.lifespan_context
        if params.name not in state.tools:
            return error(f"Unknown tool: {params.name}")
        upstream, tool = state.tools[params.name]
        return await state.clients[upstream].call_tool(tool.name, params.arguments or {})

    return Server("tollgate", lifespan=lifespan, on_list_tools=list_tools, on_call_tool=call_tool)
