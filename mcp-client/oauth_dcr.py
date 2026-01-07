"""OAuth 2.1 Dynamic Client Registration (DCR) implementation for MCP clients with token caching."""

import asyncio
import hashlib
import json
import secrets
import webbrowser
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

import httpx


class TokenCache:
    """Handles persistent token storage."""

    def __init__(self, cache_file: Path):
        self.cache_file = cache_file
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)

    def save(self, data: dict):
        """Save token data to cache."""
        with open(self.cache_file, 'w') as f:
            json.dump(data, f, indent=2)

    def load(self) -> Optional[dict]:
        """Load token data from cache."""
        if not self.cache_file.exists():
            return None

        try:
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None

    def clear(self):
        """Clear cached tokens."""
        if self.cache_file.exists():
            self.cache_file.unlink()


class OAuthDCRClient:
    """
    OAuth 2.1 DCR client with PKCE support and token caching for MCP servers.

    Implements:
    - RFC 9728: OAuth 2.0 Protected Resource Metadata
    - RFC 8414: OAuth 2.0 Authorization Server Metadata
    - RFC 7591: OAuth 2.0 Dynamic Client Registration
    - RFC 7636: PKCE (Proof Key for Code Exchange)
    - RFC 8707: Resource Indicators

    Features:
    - Token caching: Stores tokens locally and reuses them
    - Automatic refresh: Refreshes expired tokens automatically
    - Minimal user interaction: Only prompts for auth when necessary
    """

    def __init__(self, resource_server_url: str, callback_port: int = 8888, cache_dir: Optional[Path] = None):
        """
        Initialize OAuth DCR client.

        Args:
            resource_server_url: The MCP server URL (e.g., "http://localhost:3000")
            callback_port: Port for local OAuth callback server
            cache_dir: Directory for token cache (defaults to ~/.mcp/cache)
        """
        self.resource_server_url = resource_server_url.rstrip('/')
        self.callback_port = callback_port
        self.redirect_uri = f"http://localhost:{callback_port}/callback"

        # Set up token cache
        if cache_dir is None:
            cache_dir = Path.home() / ".mcp" / "cache"
        # Create a safe filename from the server URL
        cache_filename = hashlib.sha256(self.resource_server_url.encode()).hexdigest()[:16] + ".json"
        self.token_cache = TokenCache(cache_dir / cache_filename)

        # OAuth endpoints (discovered dynamically)
        self.authorization_endpoint: Optional[str] = None
        self.token_endpoint: Optional[str] = None
        self.registration_endpoint: Optional[str] = None

        # Client credentials (obtained via DCR or loaded from cache)
        self.client_id: Optional[str] = None
        self.client_secret: Optional[str] = None

        # Access token
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expires_at: Optional[datetime] = None

        # Required scope for MCP
        self.required_scopes = ["mcp:tools"]

        # PKCE parameters
        self.code_verifier: Optional[str] = None
        self.code_challenge: Optional[str] = None

    def _generate_pkce_pair(self) -> tuple[str, str]:
        """
        Generate PKCE code_verifier and code_challenge.

        Returns:
            Tuple of (code_verifier, code_challenge)
        """
        # Generate a cryptographically random code_verifier (43-128 chars)
        code_verifier = secrets.token_urlsafe(96)[:128]

        # Create code_challenge using S256 method
        import base64
        challenge_bytes = hashlib.sha256(code_verifier.encode('ascii')).digest()
        code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('ascii').rstrip('=')

        return code_verifier, code_challenge

    def _is_token_expired(self) -> bool:
        """Check if the current access token is expired."""
        if not self.token_expires_at:
            return True
        # Add 60 second buffer to avoid edge cases
        return datetime.now() >= (self.token_expires_at - timedelta(seconds=60))

    def _load_from_cache(self) -> bool:
        """
        Load credentials and tokens from cache.

        Returns:
            True if valid cached data was loaded, False otherwise
        """
        cached = self.token_cache.load()
        if not cached:
            return False

        # Validate required fields
        required_fields = ['client_id', 'client_secret', 'authorization_endpoint', 'token_endpoint']
        if not all(field in cached for field in required_fields):
            return False

        # Load OAuth endpoints
        self.authorization_endpoint = cached['authorization_endpoint']
        self.token_endpoint = cached['token_endpoint']
        self.registration_endpoint = cached.get('registration_endpoint')

        # Load client credentials
        self.client_id = cached['client_id']
        self.client_secret = cached['client_secret']

        # Load tokens
        self.access_token = cached.get('access_token')
        self.refresh_token = cached.get('refresh_token')

        # Parse expiration time
        if cached.get('expires_at'):
            self.token_expires_at = datetime.fromisoformat(cached['expires_at'])

        print(f"✓ Loaded cached credentials for {self.resource_server_url}")

        return True

    def _save_to_cache(self):
        """Save current credentials and tokens to cache."""
        cache_data = {
            'resource_server_url': self.resource_server_url,
            'authorization_endpoint': self.authorization_endpoint,
            'token_endpoint': self.token_endpoint,
            'registration_endpoint': self.registration_endpoint,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'expires_at': self.token_expires_at.isoformat() if self.token_expires_at else None,
        }
        self.token_cache.save(cache_data)
        print(f"✓ Cached credentials and tokens")

    async def discover_protected_resource_metadata(self) -> dict:
        """
        Discover OAuth Protected Resource Metadata (RFC 9728).

        Returns:
            Protected resource metadata dict
        """
        metadata_url = f"{self.resource_server_url}/.well-known/oauth-protected-resource"

        async with httpx.AsyncClient() as client:
            response = await client.get(metadata_url)
            response.raise_for_status()
            metadata = response.json()

        print(f"✓ Discovered protected resource metadata")

        return metadata

    async def discover_authorization_server_metadata(self, issuer_url: str) -> dict:
        """
        Discover OAuth Authorization Server Metadata (RFC 8414).

        Args:
            issuer_url: The authorization server issuer URL

        Returns:
            Authorization server metadata dict
        """
        # Construct well-known URL
        issuer_url = issuer_url.rstrip('/')
        metadata_url = f"{issuer_url}/.well-known/openid-configuration"

        async with httpx.AsyncClient() as client:
            response = await client.get(metadata_url)
            response.raise_for_status()
            metadata = response.json()

        self.authorization_endpoint = metadata.get('authorization_endpoint')
        self.token_endpoint = metadata.get('token_endpoint')
        self.registration_endpoint = metadata.get('registration_endpoint')

        print(f"✓ Discovered authorization server metadata")

        return metadata

    async def register_client(self) -> dict:
        """
        Register client using Dynamic Client Registration (RFC 7591).

        Returns:
            Client registration response dict
        """
        if not self.registration_endpoint:
            raise ValueError("Registration endpoint not discovered. Call discover_authorization_server_metadata first.")

        registration_request = {
            "client_name": "MCP Python Client",
            "redirect_uris": [self.redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic",
            "scope": " ".join(self.required_scopes)
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.registration_endpoint,
                json=registration_request,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            registration_response = response.json()

        self.client_id = registration_response.get('client_id')
        self.client_secret = registration_response.get('client_secret')

        print(f"✓ Registered client via DCR")

        return registration_response

    def _start_callback_server(self) -> tuple[asyncio.Future, object]:
        """
        Start a local HTTP server to receive OAuth callback.

        Returns:
            Tuple of (future that resolves to authorization code, app instance)
        """
        from aiohttp import web

        # Create a future to hold the authorization code
        code_future = asyncio.Future()

        async def callback_handler(request):
            """Handle OAuth callback."""
            query_params = request.query

            if 'code' in query_params:
                code = query_params['code']
                if not code_future.done():
                    code_future.set_result(code)

                return web.Response(
                    text="""
                    <html>
                        <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                            <h1 style="color: green;">✓ Authorization successful!</h1>
                            <p>You can close this window and return to the terminal.</p>
                        </body>
                    </html>
                    """,
                    content_type='text/html'
                )
            elif 'error' in query_params:
                error = query_params.get('error')
                error_description = query_params.get('error_description', 'No description')
                if not code_future.done():
                    code_future.set_exception(Exception(f"OAuth error: {error} - {error_description}"))

                return web.Response(
                    text=f"""
                    <html>
                        <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                            <h1 style="color: red;">✗ Authorization failed</h1>
                            <p><strong>Error:</strong> {error}</p>
                            <p>{error_description}</p>
                        </body>
                    </html>
                    """,
                    content_type='text/html'
                )

            return web.Response(text="Invalid callback", status=400)

        app = web.Application()
        app.router.add_get('/callback', callback_handler)

        return code_future, app

    async def authorize(self) -> str:
        """
        Perform authorization code flow with PKCE.

        Opens browser for user to authenticate and consent.
        Starts local server to receive callback.

        Returns:
            Authorization code
        """
        if not self.authorization_endpoint or not self.client_id:
            raise ValueError("Must discover endpoints and register client first")

        # Generate PKCE parameters
        self.code_verifier, self.code_challenge = self._generate_pkce_pair()

        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)

        # Build authorization URL with resource parameter (RFC 8707)
        auth_params = {
            'client_id': self.client_id,
            'response_type': 'code',
            'redirect_uri': self.redirect_uri,
            'scope': ' '.join(self.required_scopes),
            'state': state,
            'code_challenge': self.code_challenge,
            'code_challenge_method': 'S256',
            'resource': self.resource_server_url  # RFC 8707: Resource Indicators
        }

        auth_url = f"{self.authorization_endpoint}?{urlencode(auth_params)}"

        print(f"\n⚠ User authorization required")
        print(f"✓ Opening browser for authorization...")
        print(f"  If browser doesn't open, visit: {auth_url}\n")

        # Start callback server
        from aiohttp import web
        code_future, app = self._start_callback_server()
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, 'localhost', self.callback_port)
        await site.start()

        # Open browser
        webbrowser.open(auth_url)

        try:
            # Wait for authorization code
            code = await asyncio.wait_for(code_future, timeout=300)  # 5 minute timeout
            print(f"✓ Received authorization code")
            return code
        finally:
            await runner.cleanup()

    async def exchange_code_for_token(self, code: str) -> dict:
        """
        Exchange authorization code for access token.

        Args:
            code: Authorization code from authorize()

        Returns:
            Token response dict
        """
        if not self.token_endpoint or not self.client_id:
            raise ValueError("Must discover endpoints and register client first")

        # Prepare token request with resource parameter (RFC 8707)
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code_verifier': self.code_verifier,
            'redirect_uri': self.redirect_uri,
            'resource': self.resource_server_url  # RFC 8707: Resource Indicators
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.token_endpoint,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response.raise_for_status()
            token_response = response.json()

        self.access_token = token_response.get('access_token')
        self.refresh_token = token_response.get('refresh_token')

        # Calculate expiration time
        expires_in = token_response.get('expires_in', 3600)  # Default to 1 hour
        self.token_expires_at = datetime.now() + timedelta(seconds=expires_in)

        print(f"✓ Obtained access token (expires in {expires_in}s)")

        return token_response

    async def refresh_access_token(self) -> dict:
        """
        Refresh the access token using the refresh token.

        Returns:
            Token response dict
        """
        if not self.refresh_token:
            raise ValueError("No refresh token available")

        if not self.token_endpoint:
            raise ValueError("Token endpoint not configured")

        token_data = {
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'resource': self.resource_server_url
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.token_endpoint,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response.raise_for_status()
            token_response = response.json()

        self.access_token = token_response.get('access_token')
        # Some servers issue new refresh tokens
        if 'refresh_token' in token_response:
            self.refresh_token = token_response['refresh_token']

        # Update expiration
        expires_in = token_response.get('expires_in', 3600)
        self.token_expires_at = datetime.now() + timedelta(seconds=expires_in)

        print(f"✓ Refreshed access token (expires in {expires_in}s)")

        # Save updated tokens to cache
        self._save_to_cache()

        return token_response

    async def ensure_valid_token(self) -> str:
        """
        Ensure we have a valid access token, refreshing or re-authorizing if needed.

        This is the main method to call before making authenticated requests.

        Returns:
            Valid access token
        """
        # Try to load from cache first
        if not self.access_token:
            self._load_from_cache()

        # If we have a token but it's expired, try to refresh
        if self.access_token and self._is_token_expired():
            if self.refresh_token:
                try:
                    print("⚠ Token expired, refreshing...")
                    await self.refresh_access_token()
                    return self.access_token
                except Exception as e:
                    print(f"⚠ Token refresh failed: {e}")
                    print("  Will perform full authorization flow")
                    self.access_token = None

        # If we still don't have a token, perform full flow
        if not self.access_token:
            await self.perform_full_flow()

        return self.access_token

    async def perform_full_flow(self) -> str:
        """
        Perform complete OAuth DCR flow (discovery, registration, authorization, token exchange).

        Returns:
            Access token
        """
        print(f"\n=== Starting OAuth DCR Flow ===")
        print(f"Resource server: {self.resource_server_url}\n")

        # Step 1: Discover protected resource metadata
        prm = await self.discover_protected_resource_metadata()

        if not prm.get('authorization_servers'):
            raise ValueError("No authorization servers found in protected resource metadata")

        auth_server_url = prm['authorization_servers'][0]

        # Step 2: Discover authorization server metadata
        await self.discover_authorization_server_metadata(auth_server_url)

        # Step 3: Register client via DCR (unless we have cached credentials)
        if not self.client_id:
            await self.register_client()

        # Step 4: Authorize (opens browser)
        code = await self.authorize()

        # Step 5: Exchange code for token
        await self.exchange_code_for_token(code)

        # Step 6: Save to cache for future use
        self._save_to_cache()

        print(f"\n=== OAuth DCR Flow Complete ===\n")

        return self.access_token

    def get_auth_headers(self) -> dict:
        """
        Get HTTP headers with Bearer token for authenticated requests.

        Returns:
            Dict with Authorization header

        Raises:
            ValueError: If no access token is available
        """
        if not self.access_token:
            raise ValueError("No access token available. Call ensure_valid_token() first.")

        return {
            "Authorization": f"Bearer {self.access_token}"
        }

    def clear_cache(self):
        """Clear all cached credentials and tokens."""
        self.token_cache.clear()
        self.access_token = None
        self.refresh_token = None
        self.client_id = None
        self.client_secret = None
        print("✓ Cleared cached credentials")
