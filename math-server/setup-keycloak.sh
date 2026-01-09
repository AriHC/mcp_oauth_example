#!/bin/bash
set -e

# Keycloak Setup Script for MCP OAuth Example
# This script automates the Keycloak configuration needed for the math-server

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
ADMIN_USER="${KEYCLOAK_ADMIN:-admin}"
ADMIN_PASS="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
REALM="master"

echo "=== Keycloak Setup for MCP OAuth Example ==="
echo "Keycloak URL: $KEYCLOAK_URL"
echo "Realm: $REALM"
echo ""

# Wait for Keycloak to be ready
echo "⏳ Waiting for Keycloak to be ready..."
MAX_RETRIES=30
RETRY_COUNT=0
while ! curl -sf "$KEYCLOAK_URL/realms/master/.well-known/openid-configuration" > /dev/null 2>&1; do
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
        echo "❌ Keycloak did not become ready in time"
        echo "   Make sure Keycloak is running:"
        echo "   docker run -p 127.0.0.1:8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak start-dev"
        exit 1
    fi
    echo "   Waiting... (attempt $RETRY_COUNT/$MAX_RETRIES)"
    sleep 2
done
echo "✓ Keycloak is ready"
echo ""

# Get admin access token
echo "🔑 Authenticating with Keycloak admin..."
TOKEN_RESPONSE=$(curl -sf -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
    -d "client_id=admin-cli" \
    -d "username=$ADMIN_USER" \
    -d "password=$ADMIN_PASS" \
    -d "grant_type=password")

if [ $? -ne 0 ]; then
    echo "❌ Failed to authenticate with Keycloak"
    echo "   Check your admin credentials (default: admin/admin)"
    exit 1
fi

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
echo "✓ Authenticated successfully"
echo ""

# Create mcp:tools client scope
echo "📝 Creating 'mcp:tools' client scope..."
SCOPE_EXISTS=$(curl -sf -H "Authorization: Bearer $ACCESS_TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM/client-scopes" | grep -o '"name":"mcp:tools"' || true)

if [ -n "$SCOPE_EXISTS" ]; then
    echo "⚠  Client scope 'mcp:tools' already exists, skipping"
else
    curl -sf -X POST "$KEYCLOAK_URL/admin/realms/$REALM/client-scopes" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "mcp:tools",
            "description": "MCP Tools Scope",
            "protocol": "openid-connect",
            "attributes": {
                "include.in.token.scope": "true",
                "display.on.consent.screen": "true"
            }
        }' > /dev/null
    echo "✓ Created client scope 'mcp:tools'"
fi

# Get the scope ID using Python for reliability
echo "🔍 Getting mcp:tools scope ID..."
ALL_SCOPES=$(curl -sf -H "Authorization: Bearer $ACCESS_TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM/client-scopes")

SCOPE_ID=$(echo "$ALL_SCOPES" | python3 -c '
import sys, json
scopes = json.load(sys.stdin)
for s in scopes:
    if s.get("name") == "mcp:tools":
        print(s.get("id", ""))
        break
' 2>/dev/null)

if [ -z "$SCOPE_ID" ]; then
    echo "❌ Failed to get mcp:tools scope ID"
    exit 1
fi
echo "✓ Got scope ID: $SCOPE_ID"

# Add audience mapper to the scope
echo "🔧 Configuring audience mapper..."

# Check if mapper already exists
EXISTING_MAPPERS=$(curl -sf -H "Authorization: Bearer $ACCESS_TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM/client-scopes/$SCOPE_ID/protocol-mappers/models")

MAPPER_EXISTS=$(echo "$EXISTING_MAPPERS" | grep -o '"name":"audience-config"' || true)

if [ -n "$MAPPER_EXISTS" ]; then
    echo "⚠  Audience mapper already exists, skipping"
else
    MAPPER_RESPONSE=$(curl -sf -X POST "$KEYCLOAK_URL/admin/realms/$REALM/client-scopes/$SCOPE_ID/protocol-mappers/models" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "audience-config",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "consentRequired": false,
            "config": {
                "included.custom.audience": "http://localhost:3000",
                "access.token.claim": "true",
                "id.token.claim": "false"
            }
        }')

    if [ $? -eq 0 ]; then
        echo "✓ Audience mapper created"
    else
        echo "❌ Failed to create audience mapper"
        echo "   Response: $MAPPER_RESPONSE"
        exit 1
    fi
fi
echo ""

# Add mcp:tools scope as default optional scope for dynamically registered clients
echo "🔧 Adding mcp:tools as default optional scope..."

# Check if already added
DEFAULT_SCOPES=$(curl -sf -H "Authorization: Bearer $ACCESS_TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM/default-optional-client-scopes")

ALREADY_DEFAULT=$(echo "$DEFAULT_SCOPES" | python3 -c '
import sys, json
scopes = json.load(sys.stdin)
for s in scopes:
    if s.get("name") == "mcp:tools":
        print("yes")
        break
' 2>/dev/null)

if [ "$ALREADY_DEFAULT" = "yes" ]; then
    echo "⚠  mcp:tools is already a default optional scope, skipping"
else
    # Add as default optional scope
    ADD_RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT "$KEYCLOAK_URL/admin/realms/$REALM/default-optional-client-scopes/$SCOPE_ID" \
        -H "Authorization: Bearer $ACCESS_TOKEN")

    HTTP_CODE=$(echo "$ADD_RESPONSE" | tail -n 1)

    if [ "$HTTP_CODE" = "204" ] || [ "$HTTP_CODE" = "200" ]; then
        echo "✓ Added mcp:tools as default optional scope"
    else
        echo "❌ Failed to add mcp:tools as default optional scope (HTTP $HTTP_CODE)"
        echo "   Response: $(echo "$ADD_RESPONSE" | head -n -1)"
        exit 1
    fi
fi
echo ""

# Create test-client for server
echo "🔐 Creating 'test-client' for MCP server..."

# Get all clients and extract test-client ID using python3
ALL_CLIENTS=$(curl -sf -H "Authorization: Bearer $ACCESS_TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM/clients")

CLIENT_ID=$(echo "$ALL_CLIENTS" | python3 -c '
import sys, json
clients = json.load(sys.stdin)
for c in clients:
    if c.get("clientId") == "test-client":
        print(c.get("id", ""))
        break
' 2>/dev/null)

if [ -n "$CLIENT_ID" ]; then
    echo "⚠  Client 'test-client' already exists (ID: $CLIENT_ID)"
else
    # Create the client (Keycloak will auto-generate a secure client secret)
    echo "Creating new client 'test-client'..."
    curl -sf -X POST "$KEYCLOAK_URL/admin/realms/$REALM/clients" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "clientId": "test-client",
            "name": "MCP Server Test Client",
            "description": "Client for MCP server to validate tokens via introspection",
            "enabled": true,
            "clientAuthenticatorType": "client-secret",
            "serviceAccountsEnabled": true,
            "standardFlowEnabled": false,
            "directAccessGrantsEnabled": false,
            "publicClient": false,
            "protocol": "openid-connect",
            "redirectUris": ["*"],
            "webOrigins": ["*"],
            "attributes": {
                "oauth2.device.authorization.grant.enabled": "false",
                "oidc.ciba.grant.enabled": "false"
            }
        }' > /dev/null

    # Wait a moment for Keycloak to finish creating the client
    sleep 1

    # Get the newly created client ID
    ALL_CLIENTS=$(curl -sf -H "Authorization: Bearer $ACCESS_TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM/clients")

    CLIENT_ID=$(echo "$ALL_CLIENTS" | python3 -c '
import sys, json
clients = json.load(sys.stdin)
for c in clients:
    if c.get("clientId") == "test-client":
        print(c.get("id", ""))
        break
' 2>/dev/null)

    if [ -n "$CLIENT_ID" ]; then
        echo "✓ Created client 'test-client' (ID: $CLIENT_ID)"
    fi
fi

if [ -z "$CLIENT_ID" ]; then
    echo "❌ Failed to get client ID for test-client"
    exit 1
fi

echo ""

# Get client secret
echo "🔑 Retrieving client secret..."
CLIENT_SECRET_JSON=$(curl -sf -H "Authorization: Bearer $ACCESS_TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM/clients/$CLIENT_ID/client-secret")

if [ $? -ne 0 ] || [ -z "$CLIENT_SECRET_JSON" ]; then
    echo "❌ Failed to retrieve client secret from Keycloak API"
    echo "   Client ID: $CLIENT_ID"
    echo "   URL: $KEYCLOAK_URL/admin/realms/$REALM/clients/$CLIENT_ID/client-secret"
    exit 1
fi

echo "   Raw response: $CLIENT_SECRET_JSON"

# Extract the secret value from JSON response using python3
CLIENT_SECRET=$(echo "$CLIENT_SECRET_JSON" | python3 -c 'import sys, json; data = json.load(sys.stdin); print(data.get("value", ""))' 2>/dev/null)

# Fallback to grep/sed if python3 fails
if [ -z "$CLIENT_SECRET" ]; then
    CLIENT_SECRET=$(echo "$CLIENT_SECRET_JSON" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p')
fi

if [ -z "$CLIENT_SECRET" ]; then
    echo "❌ Failed to extract client secret from response:"
    echo "   Response: $CLIENT_SECRET_JSON"
    exit 1
fi

echo "✓ Client secret retrieved: ${CLIENT_SECRET:0:10}..."
echo ""

# Create .env file
echo "📄 Creating .env file..."
cat > .env << EOF
# Keycloak OAuth Configuration
OAUTH_CLIENT_ID=test-client
OAUTH_CLIENT_SECRET=$CLIENT_SECRET

# Server Configuration
HOST=localhost
PORT=3000

# Auth Server Configuration
AUTH_HOST=localhost
AUTH_PORT=8080
AUTH_REALM=master

# MCP Configuration
MCP_SCOPE=mcp:tools
TRANSPORT=streamable-http
EOF

echo "✓ Created .env file with credentials"
echo ""

echo "=== ✅ Keycloak Setup Complete! ==="
echo ""
echo "Your configuration:"
echo "  Client ID:     test-client"
echo "  Client Secret: $CLIENT_SECRET"
echo ""
echo "To start the MCP server:"
echo "  uv run server.py"
echo ""
echo "The server will be available at: http://localhost:3000"
echo "OAuth metadata: http://localhost:3000/.well-known/oauth-protected-resource"
