# 릴리스 / 자동 업데이트 운영 메모

데스크톱 자동 업데이트는 Tauri updater(minisign 서명) 사용. Authenticode
코드 서명은 미적용: 설치 시 SmartScreen 경고는 남지만 업데이트 무결성은
minisign 으로 검증됨.

## 서명 키 (절대 커밋 금지)

- 키쌍: `.updater-keys/ashfield-sync.key` (private) / `.key.pub` (public)
- `.updater-keys/` 는 .gitignore: private 키는 빌드 환경 secret 으로만 보관
  (GitHub Actions 로 빌드한다면 repository secret 으로 등록)
- 공개키는 `src-tauri/tauri.conf.json` 의 `plugins.updater.pubkey` 에 박혀 있음
- **분실 시 업데이트 영구 불가**: 안전한 곳에 백업
- 키 재생성: `npx tauri signer generate -w .updater-keys/ashfield-sync.key --ci -p ""`
  → 새 `.key.pub` 내용을 `pubkey` 에 반영 (기존 설치본은 자동 업데이트 불가해짐)

## 릴리스 빌드

```bash
# private 키를 환경변수로 (빈 패스워드)
export TAURI_SIGNING_PRIVATE_KEY="$(cat .updater-keys/ashfield-sync.key)"
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD=""

npm run tauri build
```

`createUpdaterArtifacts: true` 라 빌드 산출물에 설치 파일(`.msi` / `-setup.exe`)과
각각의 `.sig` 가 생성됨 (`src-tauri/target/release/bundle/`).

Linux 는 Linux 에서 빌드: `.deb`, `.rpm`, `.AppImage` 가 나온다. 자동 업데이트는
AppImage 만 지원 (`.AppImage.sig`). deb/rpm 설치본은 새 패키지를 직접 설치.

## 로그인 설정 (빌드 시 고정)

로그인은 Ashfield 계정 서버(OIDC)로 한다: Keycloak 아님. 계약:
`ashfield-account/docs/adr/0001-account-server-contract.md`.
`VITE_*` 값은 빌드 때 박히므로 릴리스 빌드 전에 `.env` 를 운영 값으로:

| 변수 | 운영 예 | 비고 |
|---|---|---|
| `VITE_ACCOUNT_URL` | `https://account.example.com` | 계정 서버 issuer (디스커버리) |
| `VITE_DRIVE_URL` | `https://drive.example.com` | Drive API base: `capabilities/default.json` allowlist 에도 추가 |
| `VITE_DRIVE_RESOURCE` | `https://drive.example.com` | 계정 서버의 `DRIVE_URL`, Drive 백엔드의 `AUTH_AUDIENCE` 와 **정확히** 같게 |
| `VITE_OAUTH_CLIENT_ID` | `ashfield-sync` | |
| `VITE_OAUTH_REDIRECT_PORT` | `1421` | 계정 서버 `SYNC_REDIRECT_URIS` 에 `http://127.0.0.1:1421/oauth/callback` 등록 필요 |

## 배포 (GitHub Releases)

업데이트 endpoint:
`https://github.com/ashfieldlab/ashfield-sync/releases/latest/download/latest.json`
(tauri.conf.json 의 plugins.updater.endpoints).

1. `vX.Y.Z` 태그로 GitHub Release 생성 후 설치 파일과 `latest.json` 을 asset 으로 업로드.
   `latest.json` 형식:
   ```json
   {
     "version": "0.2.0",
     "notes": "변경사항",
     "pub_date": "2026-06-13T00:00:00Z",
     "platforms": {
       "windows-x86_64": {
         "signature": "<-setup.exe.sig 내용>",
         "url": "https://github.com/ashfieldlab/ashfield-sync/releases/download/v0.2.0/Ashfield.Sync_0.2.0_x64-setup.exe"
       },
       "linux-x86_64": {
         "signature": "<.AppImage.sig 내용>",
         "url": "https://github.com/ashfieldlab/ashfield-sync/releases/download/v0.2.0/Ashfield.Sync_0.2.0_amd64.AppImage"
       }
     }
   }
   ```
   (GitHub 는 asset 파일명의 공백을 `.` 으로 바꿈: 실제 업로드된 asset URL 을 확인해서 기입.)
2. "latest" release 로 표시되어야 `releases/latest/download/latest.json` 이 새 버전을 가리킴.
3. 클라이언트는 부팅 시 + 설정의 '업데이트 확인' 으로 latest.json 의 version 을
   현재와 비교 → 높으면 다운로드/서명검증/설치/재시작.

endpoint 가 아직 없으면 클라이언트는 조용히 "최신 버전" 으로 처리.
