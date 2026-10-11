# 설정과 로그인

## 서버 주소

로그인 화면에서 Drive 주소(예: `drive.example.com`)를 입력합니다.
앱은 `<Drive 주소>/api/client-config` 에서 계정 서버 주소를 받아 저장하고, API 는 같은 주소의 `/api/v1` 로 부릅니다.
토큰의 `aud` 는 Drive 의 공개 주소(`BETTER_AUTH_URL`)이므로 Account 의 `DRIVE_URL`, Drive 백엔드의 `AUTH_AUDIENCE` 와 같아야 합니다.

## 환경 변수

`.env.example` 을 `.env` 로 복사합니다. 값은 빌드할 때 앱에 들어갑니다.

| 변수 | 기본값 | 설명 |
|---|---|---|
| `VITE_DRIVE_URL` | (없음) | 로그인 화면의 Drive 주소 기본값 |
| `VITE_OAUTH_CLIENT_ID` | `ashfield-sync` | Account 에 등록된 클라이언트 |
| `VITE_OAUTH_REDIRECT_PORT` | `1421` | 로그인 콜백 포트 |

## 로그인 방식

[Ashfield Account](https://github.com/ashfieldlab/ashfield-account) 에 표준 OIDC 공개 클라이언트로 로그인합니다
(계약: `ashfield-account/docs/adr/0001-account-server-contract.md`).

- 브라우저로 로그인하고 `http://127.0.0.1:1421/oauth/callback` 으로 돌아옵니다. PKCE, `state`, `nonce`, `iss` 를 검증합니다.
- `offline_access` 로 리프레시 토큰을 받고, 모든 요청에 `resource` 를 붙여 JWT 액세스 토큰을 받습니다.
- 리프레시 토큰은 OS 비밀 저장소에 저장합니다 (Windows 자격 증명 관리자, Linux Secret Service).

**리프레시 토큰 회전**: 갱신할 때마다 새 토큰이 오고, 옛 토큰을 다시 쓰면 서버가 토큰 묶음 전체를 폐기합니다.
그래서 앱의 모든 갱신은 `src-tauri/src/oauth.rs` 의 잠금 하나를 거치며, UI, SSE, Files On-Demand 가 같은 액세스 토큰을 공유합니다.

**로그아웃** 은 서버에서 리프레시 토큰을 폐기하고 비밀 저장소에서 지웁니다.
기기를 원격으로 끊으려면 Account 의 "연결된 앱"을 사용하세요.
