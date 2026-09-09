"""MCP adaptation of an already Principal-bound PDI consumer runtime."""

from typing import Any

from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server import MCPServer
from mcp.shared.exceptions import MCPError
from mcp_types import INVALID_PARAMS

from pdi.consumer import PrincipalBoundConsumerRuntime

from .server import create_server


_FORBIDDEN_AUTHORIZATION_ARGUMENTS = frozenset({
    "principal_id",
    "principal",
    "database",
    "database_url",
    "database_ref",
    "db",
    "scope_id",
    "observation_scope_id",
    "provider_account_id",
    "credential",
    "credential_ref",
    "binding_ref",
    "api_key",
    "password",
    "secret",
})


class _RejectAuthorizationArguments:
    async def __call__(
        self,
        context: ServerRequestContext[Any, Any],
        call_next: CallNext,
    ) -> HandlerResult:
        if context.method == "tools/call" and context.params:
            arguments = context.params.get("arguments")
            if isinstance(arguments, dict) and (
                set(arguments) & _FORBIDDEN_AUTHORIZATION_ARGUMENTS
            ):
                raise MCPError(
                    INVALID_PARAMS,
                    "Tool authorization selectors are not accepted",
                )
        return await call_next(context)


def create_principal_bound_server(
    runtime: PrincipalBoundConsumerRuntime,
) -> MCPServer:
    """Expose only business reads; Principal routing already happened."""

    if not isinstance(runtime, PrincipalBoundConsumerRuntime):
        raise TypeError("Principal-bound consumer runtime is required")
    server = create_server(
        runtime.query_service,
        runtime.observation_reader,
        retrieval_service=None,
        rich_retrieval_service=runtime.rich_retrieval_service,
        data_status_service=None,
        resource_query_service=runtime.resource_query_service,
        resource_text_service=runtime.resource_text_service,
        resource_access_service=runtime.resource_access_service,
        resource_access_close=runtime.aclose,
    )
    server.middleware.insert(0, _RejectAuthorizationArguments())
    return server
