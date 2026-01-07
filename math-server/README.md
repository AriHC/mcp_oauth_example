A simple authenticating MCP server, taken from https://modelcontextprotocol.io/docs/tutorials/security/authorization

# To Run:

1) Set up keycloak as described at https://modelcontextprotocol.io/docs/tutorials/security/authorization#keycloak-setup
  * When told to note the client secret, save it in an OAUTH_CLIENT_SECRET env variable
  * Note that in addition to those instructions I also had to add "*" to the "test-client" valid redirect URIs. 
  
2) uv run server.py

This can be tested by either further following the directions on the linked page to test with VSCode (note 1/7/26: VSCode MCP
has a bug with OAuth DCR integration. This was _just_ fixed yesterday and released in the Insiders edition, but may not work
in the standard release yet. https://github.com/microsoft/vscode/issues/279955), or with the http_client in ../mcp-client/