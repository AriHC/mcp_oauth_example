"""HTTP MCP client with OAuth authentication support."""

import asyncio
import sys
from contextlib import AsyncExitStack
from typing import Optional

import httpx
from anthropic import Anthropic
from dotenv import load_dotenv
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from oauth_dcr import OAuthDCRClient

# Python 3.11+ has ExceptionGroup built-in
try:
    ExceptionGroup
except NameError:
    from exceptiongroup import ExceptionGroup

load_dotenv()


class MCPHTTPClient:
    """
    MCP client that connects to HTTP-based MCP servers with OAuth authentication.

    Supports:
    - Lazy authentication: Only authenticates when server returns 401
    - OAuth 2.1 with Dynamic Client Registration (DCR)
    - Automatic token refresh
    - Token caching for seamless reconnection
    """

    def __init__(self, server_url: str):
        """
        Initialize HTTP MCP client.

        Args:
            server_url: URL of the MCP server (e.g., "http://localhost:3000")
        """
        self.server_url = server_url.rstrip('/')
        self.oauth_client: Optional[OAuthDCRClient] = None
        self.anthropic = Anthropic()
        self.http_client: Optional[httpx.AsyncClient] = None
        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        self.authenticated = False

    async def connect(self):
        """
        Connect to the MCP server.

        Checks if server requires OAuth before connecting.
        Only performs OAuth flow if server requires it.
        """
        print(f"\n=== Connecting to MCP Server ===")
        print(f"Server URL: {self.server_url}\n")

        # Check if server requires OAuth by probing metadata endpoint
        requires_auth = await self._check_if_auth_required()

        if requires_auth:
            # Server requires authentication, handle OAuth
            await self._handle_auth_required()

        # Now connect with or without auth
        await self._connect(authenticated=requires_auth)

        # List tools to show what's available
        response = await self.session.list_tools()
        tools = response.tools
        print(f"✓ Connected to server")
        print(f"  Available tools: {[tool.name for tool in tools]}\n")

    async def _check_if_auth_required(self) -> bool:
        """
        Check if the server requires OAuth authentication.

        Does this by checking for the OAuth Protected Resource metadata endpoint.
        Note: ideally this would happen "on demand" when a 401 is received, but
        due to limitations in the MCP SDK's HTTP transport's error handling,
        it's simpler to check ahead of time.

        Returns:
            True if OAuth is required, False otherwise
        """
        try:
            async with httpx.AsyncClient() as client:
                # Try to get OAuth metadata
                response = await client.get(f"{self.server_url}/.well-known/oauth-protected-resource")
                if response.status_code == 200:
                    # Server advertises OAuth support
                    return True
        except:
            pass

        return False

    async def _connect(self, authenticated: bool):
        """
        Connect to the MCP server.

        Args:
            authenticated: Whether to use OAuth authentication
        """
        # Create httpx client with or without auth
        if authenticated and self.oauth_client:
            headers = self.oauth_client.get_auth_headers()
            self.http_client = httpx.AsyncClient(headers=headers, timeout=30.0)
        else:
            self.http_client = httpx.AsyncClient(timeout=30.0)

        # Use MCP SDK's streamable_http_client
        streamable_http_transport = await self.exit_stack.enter_async_context(
            streamable_http_client(self.server_url, http_client=self.http_client)
        )
        read_stream, write_stream, get_session_id = streamable_http_transport

        # Create MCP ClientSession
        self.session = await self.exit_stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )

        # Initialize the session
        await self.session.initialize()

    async def _handle_auth_required(self):
        """
        Handle authentication when necessary.

        This will:
        1. Initialize OAuth client if not already done
        2. Check for cached tokens first
        3. Only prompt for browser auth if no valid cached tokens
        """
        if not self.oauth_client:
            self.oauth_client = OAuthDCRClient(self.server_url)

        print("⚠ Server requires authentication")

        # Try to load cached tokens first
        if self.oauth_client._load_from_cache():
            # We have cached credentials, check if token is valid
            if not self.oauth_client._is_token_expired():
                print("✓ Using cached access token")
                self.authenticated = True
                return
            elif self.oauth_client.refresh_token:
                # Token expired but we have refresh token
                try:
                    print("⚠ Token expired, refreshing...")
                    await self.oauth_client.refresh_access_token()
                    self.authenticated = True
                    return
                except Exception as e:
                    print(f"⚠ Token refresh failed: {e}")
                    print("  Will perform full authorization")

        # No valid cached token, perform full OAuth flow
        await self.oauth_client.perform_full_flow()
        self.authenticated = True

    async def _ensure_valid_token(self):
        """
        Ensure we have a valid access token, refreshing if necessary.
        Updates httpx client headers if token was refreshed.
        """
        if not self.authenticated or not self.oauth_client:
            return

        # Check if token is expired
        if self.oauth_client._is_token_expired():
            if self.oauth_client.refresh_token:
                try:
                    print("⚠ Token expired, refreshing...")
                    await self.oauth_client.refresh_access_token()

                    # Update httpx client headers with new token
                    if self.http_client:
                        self.http_client.headers.update(self.oauth_client.get_auth_headers())

                    print("✓ Token refreshed")
                except Exception as e:
                    print(f"✗ Token refresh failed: {e}")
                    raise

    async def process_query(self, query: str) -> str:
        """
        Process a query using Claude and available MCP tools.

        Args:
            query: User query

        Returns:
            Claude's response
        """
        if not self.session:
            raise ValueError("Not connected. Call connect() first.")

        messages = [{"role": "user", "content": query}]

        # Ensure token is valid before fetching tools
        await self._ensure_valid_token()

        # Get available tools from MCP session
        print("Fetching available tools from MCP server...")
        response = await self.session.list_tools()
        available_tools = [{
            "name": tool.name,
            "description": tool.description or "",
            "input_schema": tool.inputSchema
        } for tool in response.tools]

        # Initial Claude API call
        print("Claude call")
        response = self.anthropic.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=messages,
            tools=available_tools
        )

        # Process response and handle tool calls
        final_text = []
        assistant_message_content = []

        for content in response.content:
            if content.type == 'text':
                final_text.append(content.text)
                assistant_message_content.append(content)
            elif content.type == 'tool_use':
                tool_name = content.name
                tool_args = content.input

                # Execute tool call via MCP session
                print(f"  → Calling tool: {tool_name}")
                result = await self.session.call_tool(tool_name, tool_args)

                assistant_message_content.append(content)
                messages.append({
                    "role": "assistant",
                    "content": assistant_message_content
                })

                # Extract content from MCP result
                result_text = ""
                if hasattr(result, 'content') and result.content:
                    for content_item in result.content:
                        if hasattr(content_item, 'text'):
                            result_text += content_item.text

                messages.append({
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": content.id,
                            "content": result_text or str(result)
                        }
                    ]
                })

                # Get next response from Claude
                response = self.anthropic.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=1000,
                    messages=messages,
                    tools=available_tools
                )

                # Add Claude's final response
                for c in response.content:
                    if c.type == 'text':
                        final_text.append(c.text)

        return "\n".join(final_text)

    async def chat_loop(self):
        """Run an interactive chat loop."""
        print("\n=== MCP HTTP Client Started ===")
        print("Type your queries or 'quit' to exit.\n")

        while True:
            try:
                query = input("Query: ").strip()

                if query.lower() == 'quit':
                    break

                if not query:
                    continue

                response = await self.process_query(query)
                print(f"\n{response}\n")

            except KeyboardInterrupt:
                print("\n\nExiting...")
                break
            except Exception as e:
                print(f"\n✗ Error: {str(e)}\n")

    async def cleanup(self):
        """Clean up resources."""
        await self.exit_stack.aclose()


async def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python http_client.py <server_url>")
        print("\nExample:")
        print("  python http_client.py http://localhost:3000")
        sys.exit(1)

    server_url = sys.argv[1]

    client = MCPHTTPClient(server_url)
    try:
        await client.connect()
        await client.chat_loop()
    finally:
        await client.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
