# MCP Client/Server & OAuth Examples

This project contains 2 MCP clients and 2 MCP servers:

## Servers:
* weather/weather.py : A basic stdio MCP server, no authorization required
* math-server/server.py : An http server requiring authorization

## Clients:
* mcp-client/client.py : A basic stdio MCP client, no authorization performed
* mcp-client/http_client.py : An http MCP client, that performs Oauth with DCR as necessary

See Nested READMEs for more details.

# End-to-end Demo Instructions:

This will use 3 terminals: one for Keycloak, one for the Server, and one for
the Client.

## 0. Prerequisites
Install and update (through your package manager/other method of choice):
* uv
* docker/docker desktop

## Terminal 1: Keycloak

```bash
docker run -p 127.0.0.1:8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak start-dev
```

## Terminal 2: Server

### Configure Keycloak, Setting Server Environment

```bash
cd math-server
./setup-keycloak.sh
```

After running the above command, in a browser, navigate to localhost:8080,
and log in (the default username and password are both "admin" as set
above). Go to the "clients" panel on the left, then the "Client
Registration" tab, and select "Trusted Hosts". Disable "Client URIs Must
Match", and in the "Trusted Hosts" field add the IP address your client will
be connecting from*, hit save.
 
*(if you're not sure your client IP, an easy way to find out is to come back
to this step later - the first time you attempt to connect your client, 
you'll get a 403 error, but if you look at the keycloak logs (in terminal 1)
you should see a warning log with a CLIENT_REGISTER_ERROR with a specified
IP address - that's the one to use; apply it per the instructions above,
then re-run the client).

**Note:** if you ran an earlier version of this demo, you may have
OAUTH_CLIENT_SECRET set in your environment. Clear it, as it will
override the .env used by the newer version.

### Start the Server

```bash
uv run server.py
```

## Terminal 3: Client

### Environment Setup
The client wraps Claude, connecting a simple conversation loop to the
specified server. As such, you'll need to provide an Anthropic API key
in your environment (or the `mcp-client/.env` file):

```bash
cd mcp-client
ANTHROPIC_API_KEY=your_api_key_here
```

### Run the client

**Note:** if you have run the client against a previous Keycloak instance,
or just want to reset the Oauth step of the demo, clear the mcp cache with
`rm -rf ~/.mcp/cache`

```bash
uv run http_client.py http://localhost:3000
```

On first run, it should open a web browser to request permissions, as part
of the standard Oauth DCR flow. Subsequent runs should use cached information
to request a new token when necessary without re-requiring authentication.

**Note:** as mentioned above in the Keycloak setup section, if you encounter
a 403 you may need to mark your IP address as a trusted host

#### Use the tool!

A query like "add 21 + 55" should call the server tool for assistance.