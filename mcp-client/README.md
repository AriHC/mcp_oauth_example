Note: this README is primarily for http_client.py (since this is just for demo purposes, I haven't yet
cleaned up the directory structure/code to better merge or separate the two; client.py is simply
taken from https://modelcontextprotocol.io/docs/develop/build-client)

# MCP HTTP Client with OAuth DCR

Python client for connecting to MCP servers over HTTP with OAuth 2.1 Dynamic Client Registration support.

## Features

- **Lazy Authentication**: Only authenticates when server requires it (on 401)
- **Token Caching**: Stores OAuth tokens locally for seamless reconnection
- **Automatic Refresh**: Refreshes expired tokens automatically
- **No User Interaction** (after first auth): Subsequent runs use cached tokens
- **Dynamic Client Registration (DCR)**: Automatically registers with OAuth providers

## Setup

1. Install dependencies:
   ```bash
   uv sync
   ```

2. Set up your environment variables in `.env`:
   ```bash
   ANTHROPIC_API_KEY=your_api_key_here
   ```
3. Ensure you have an OAuth-Protected Server available. For demo purposes, consider
using math-server + keycloak (as described at https://modelcontextprotocol.io/docs/tutorials/security/authorization#keycloak-setup -
note that in addition to those instructions I also had to add "*" to the "test-client" valid redirect URIs). 
Note that math-server expects an OAUTH_CLIENT_SECRET env variable.

## Usage

### Connecting to an OAuth-Protected Server

```bash
uv run http_client.py http://localhost:3000
```

**First Run:**
- Client will attempt connection
- Server returns 401 (authentication required)
- Client checks for cached tokens
- If none found, performs OAuth DCR flow:
  - Discovers OAuth metadata
  - Registers client with authorization server
  - Opens browser for user authentication
  - Caches tokens locally

**Subsequent Runs:**
- Client loads cached tokens
- No browser window needed
- Only re-authenticates if tokens expire or are rejected

### Connecting to a Non-Authenticated Server

The client works with both authenticated and non-authenticated servers. It will only trigger OAuth if the server requires it.

```bash
# This won't trigger OAuth if server doesn't require auth
uv run http_client.py http://localhost:8080
```

## Token Cache

Tokens are cached in `~/.mcp/cache/` with filenames based on the server URL hash.

To clear cached tokens:
```bash
rm -rf ~/.mcp/cache/
```

Or clear tokens for a specific server by deleting its cache file.

## Architecture

### Components

1. **`http_client.py`**: Main MCP client
   - Handles MCP protocol over HTTP
   - Integrates with Claude API for AI-powered tool usage
   - Lazy authentication on 401

2. **`oauth_dcr.py`**: OAuth DCR implementation
   - RFC 9728: Protected Resource Metadata discovery
   - RFC 8414: Authorization Server Metadata discovery
   - RFC 7591: Dynamic Client Registration
   - RFC 7636: PKCE (Proof Key for Code Exchange)
   - RFC 8707: Resource Indicators
   - Token caching and refresh

3. **`client.py`**: Original stdio-based client (for non-HTTP servers)

## Example Session

```bash
$ uv run http_client.py http://localhost:3000

=== Connecting to MCP Server ===
Server URL: http://localhost:3000

⚠ Server requires authentication
✓ Discovered protected resource metadata
✓ Discovered authorization server metadata
✓ Registered client via DCR

⚠ User authorization required
✓ Opening browser for authorization...
# Browser opens, user authenticates...
✓ Received authorization code
✓ Obtained access token (expires in 3600s)
✓ Cached credentials and tokens

✓ Connected to server
  Available tools: ['add_numbers', 'multiply_numbers']

=== MCP HTTP Client Started ===
Type your queries or 'quit' to exit.

Query: What is 15 + 27?
  → Calling tool: add_numbers

15 + 27 equals 42.

Query: quit
```

## Troubleshooting

### Authentication Loop

If you see repeated authentication prompts, check:
- Keycloak is running (`http://localhost:8080`)
- Math-server client secret is correct
- Clear cache: `rm -rf ~/.mcp/cache/`

### Token Refresh Failures

If refresh tokens fail:
- Check if refresh tokens are enabled in Keycloak
- Clear cache and re-authenticate
- Check server logs for introspection errors

### Connection Errors

If the client can't connect:
- Verify server is running: `curl http://localhost:3000/.well-known/oauth-protected-resource`
- Check server logs for errors
- Ensure firewall allows connections on the port
