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

| Variable | Meaning |
|---|---|
| `VITE_API_URL` | Base URL of your Ashfield Drive server |
| `VITE_OAUTH_ISSUER` | OIDC issuer used for login (OAuth 2.0 + PKCE) |
| `VITE_OAUTH_CLIENT_ID` | OAuth client ID registered for this app |
| `VITE_OAUTH_REDIRECT_PORT` | Loopback callback port (default `1421`) |

These values are baked in at build time.

The app talks to the server through Tauri's HTTP plugin, which only allows hosts
on an allowlist. Add your server to the `http:default` entry in
`src-tauri/capabilities/default.json`, for example:

```json
{ "url": "https://drive.your-domain.com/*" }
```

The default list only contains `http://localhost:*` and the placeholder
`https://drive.example.com/*`.

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
