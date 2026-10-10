# 설정과 로그인

## 환경 변수

`.env.example` 을 `.env` 로 복사해 채웁니다. 값은 빌드할 때 앱에 들어갑니다.

| 변수 | 기본값 | 설명 |
|---|---|---|
| `VITE_ACCOUNT_URL` | `http://localhost:3300` | Ashfield Account 주소 (로그인) |
| `VITE_DRIVE_URL` | `http://localhost:8200` | Drive API 주소 (`/api/v1` 호출) |
| `VITE_DRIVE_RESOURCE` | `http://localhost:3200` | 토큰의 `aud`: Drive 의 공개 주소 |
| `VITE_OAUTH_CLIENT_ID` | `ashfield-sync` | Account 에 등록된 클라이언트 |
| `VITE_OAUTH_REDIRECT_PORT` | `1421` | 로그인 콜백 포트 |

`VITE_DRIVE_RESOURCE` 는 Account 의 `DRIVE_URL`, Drive 백엔드의 `AUTH_AUDIENCE` 와 같아야 합니다.
로컬에서는 API(8200)와 프론트(3200) 포트가 달라 따로 두었고, 운영에서 한 주소를 쓰면 둘 다 같은 값을 넣으면 됩니다.

Drive API 호스트는 `src-tauri/capabilities/default.json` 의 HTTP 허용 목록에도 추가해야 합니다.

```json
{ "url": "https://drive.your-domain.com/*" }
```

## 로그인 방식

[Ashfield Account](https://github.com/ashfieldlab/ashfield-account) 에 표준 OIDC 공개 클라이언트로 로그인합니다
(계약: `ashfield-account/docs/adr/0001-account-server-contract.md`).

- 브라우저로 로그인하고 `http://127.0.0.1:1421/oauth/callback` 으로 돌아옵니다. PKCE, `state`, `nonce`, `iss` 를 검증합니다.
- `offline_access` 로 리프레시 토큰을 받고, 모든 요청에 `resource` 를 붙여 JWT 액세스 토큰을 받습니다.
- 리프레시 토큰은 Windows 자격 증명 관리자에 저장합니다.

**리프레시 토큰 회전**: 갱신할 때마다 새 토큰이 오고, 옛 토큰을 다시 쓰면 서버가 토큰 묶음 전체를 폐기합니다.
그래서 앱의 모든 갱신은 `src-tauri/src/oauth.rs` 의 잠금 하나를 거치며, UI, SSE, Files On-Demand 가 같은 액세스 토큰을 공유합니다.

**로그아웃** 은 서버에서 리프레시 토큰을 폐기하고 자격 증명 관리자에서 지웁니다.
기기를 원격으로 끊으려면 Account 의 "연결된 앱"을 사용하세요.
