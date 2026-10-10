# Ashfield Sync

Windows desktop sync client for [Ashfield Drive](https://github.com/ashfieldlab/ashfield-drive).

Ashfield Sync runs in the system tray and mirrors your Ashfield Drive files into a
local folder (default `%USERPROFILE%\Ashfield`). It uses the Windows Cloud Files API
(Files On-Demand), so files appear as placeholders and are downloaded only when
opened. Local edits are uploaded automatically, and server changes arrive over SSE.

- **Windows only.** It depends on the Windows Cloud Files API. macOS and Linux are not supported.
- **Needs an Ashfield Drive server.** The app is only a client. You have to run your own server.
- Built with Tauri 2 (Rust) and React 19 + Vite.

## Configuration

Copy `.env.example` to `.env` and set:

| Variable | Default | Meaning |
|---|---|---|
| `VITE_ACCOUNT_URL` | `http://localhost:3300` | Ashfield account server (OIDC issuer). Login goes here. |
| `VITE_DRIVE_URL` | `http://localhost:8200` | Ashfield Drive **API base** (backend). All `/api/v1` calls go here. (`VITE_API_URL` is still read as a fallback.) |
| `VITE_DRIVE_RESOURCE` | `http://localhost:3200` | OAuth `resource` = the `aud` of the access token. See below. |
| `VITE_OAUTH_CLIENT_ID` | `ashfield-sync` | OAuth client registered on the account server |
| `VITE_OAUTH_REDIRECT_PORT` | `1421` | Loopback callback port |

These values are baked in at build time.

### Login (Ashfield account server)

The app signs in with the central Ashfield account server, following its contract
(`ashfield-account/docs/adr/0001-account-server-contract.md`):

- Endpoints come from `${VITE_ACCOUNT_URL}/.well-known/openid-configuration`.
  If discovery fails, the app falls back to `/api/auth/oauth2/{authorize,token,revoke}`.
- `ashfield-sync` is a public client: no secret, PKCE (S256) required, plus `state`, `nonce`
  and the RFC 9207 `iss` check on the callback.
- The redirect URI is `http://127.0.0.1:<VITE_OAUTH_REDIRECT_PORT>/oauth/callback`. It must
  match one of the account server's `SYNC_REDIRECT_URIS` exactly.
- Scope is `openid profile email offline_access`. Without `offline_access` the server issues no refresh token.
- The authorize, code-exchange and refresh requests all send `resource=<VITE_DRIVE_RESOURCE>`.
  Without it the access token is opaque, and the Drive backend can't verify it.

**Choosing `VITE_DRIVE_RESOURCE`:** the account server only accepts the resource linked
to `ashfield-sync`, which is its `DRIVE_URL` setting: the Drive **public URL**
(the frontend, `http://localhost:3200` in local dev). The Drive backend checks the
same value as `AUTH_AUDIENCE`. In local dev the API base (`:8200`) differs from the
resource (`:3200`), so they are separate settings. In production, if the frontend and API share one origin
(for example `https://drive.example.com`), both get the same value.

**Refresh tokens rotate.** Every refresh returns a new refresh token, and the old one stops working.
If an old token is sent again, the server revokes the whole token family. All refreshes
in the app go through one lock in `src-tauri/src/oauth.rs`. The UI (API 401),
the SSE reconnect and the Files On-Demand hydration threads share one access-token cache,
so only one refresh is ever in flight. The newest refresh token is written to Windows
Credential Manager after each refresh. If a refresh fails with `invalid_grant`, the
stored token is deleted and the app shows the login screen.

**Logout** revokes the refresh token at the server's `revocation_endpoint` and then clears it
from Credential Manager. This doesn't end the account server's browser session.
To disconnect the device remotely, use "연결된 앱" on the account home page.

The app talks to the Drive API through Tauri's HTTP plugin, which only allows hosts
on an allowlist. Add your Drive API host to the `http:default` entry in
`src-tauri/capabilities/default.json`, for example:

```json
{ "url": "https://drive.your-domain.com/*" }
```

The default list only contains `http://localhost:*` and the placeholder
`https://drive.example.com/*`. The account server is called only from Rust (`reqwest`),
so it doesn't need an allowlist entry.

## Development

Requires Node.js and a Rust toolchain on Windows (see the
[Tauri prerequisites](https://tauri.app/start/prerequisites/)).

```bash
npm install
npm run tauri dev
```

After the server API changes, regenerate the typed client from `openapi.json`
with `npm run gen:api`.

## Release

See [RELEASE.md](RELEASE.md) for the updater signing key, the build, and publishing to GitHub Releases.

Design notes are in [DESIGN.html](DESIGN.html).
