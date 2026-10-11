# Linux

## 준비물

Debian, Ubuntu 기준:

```bash
sudo apt install -y build-essential curl pkg-config libssl-dev libdbus-1-dev \
  libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

다른 배포판은 [Tauri 준비물](https://tauri.app/start/prerequisites/#linux) 을 보세요.

## Windows 와 다른 점

- **전체 미러**: Linux 에는 Files On-Demand 가 없어서 파일을 모두 내려받아 둡니다. 동시에 4개씩 받습니다.
- **대소문자 구분**: `a.txt` 와 `A.txt` 는 다른 파일입니다. 파일명에는 `/` 만 쓸 수 없습니다.
- **로그인 정보**: 리프레시 토큰은 Secret Service (GNOME Keyring, KWallet) 에 저장합니다. 비밀 저장소가 없는 환경에서는 매번 다시 로그인해야 합니다.
- **트레이**: AppIndicator 를 씁니다. GNOME 에서는 AppIndicator 확장이 켜져 있어야 아이콘이 보입니다 (Ubuntu 는 기본으로 켜져 있음).

## 빌드

```bash
npm run tauri build   # .deb, .rpm, AppImage
```
