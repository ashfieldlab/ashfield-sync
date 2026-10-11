<div align="center">

<img src="src/assets/ashfield-mark.svg" width="72" alt="Ashfield" />

# Ashfield Sync

Ashfield Drive 의 데스크톱 동기화 앱

[![Tauri](https://img.shields.io/badge/Tauri-2-24C8D8?style=flat-square&logo=tauri&logoColor=white)](https://tauri.app)
[![Rust](https://img.shields.io/badge/Rust-000000?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Vite](https://img.shields.io/badge/Vite-7-646CFF?style=flat-square&logo=vite&logoColor=white)](https://vite.dev)
[![Windows](https://img.shields.io/badge/Windows-0078D4?style=flat-square)](#)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat-square&logo=linux&logoColor=black)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)](LICENSE)

</div>

트레이에서 조용히 돌면서 Drive 의 파일을 내 PC 폴더(`~/Ashfield`)와 맞춰 둡니다.

- **필요할 때만 다운로드**: 파일은 자리만 차지하고, 열 때 내려받습니다 (Windows Files On-Demand, Linux 는 전체를 내려받아 둠)
- **양방향 동기화**: 로컬에서 고치면 올라가고, 서버 변경은 바로 반영됩니다
- **잠긴 폴더**: Drive 의 종단간 암호화 폴더를 PC 에서 열고 잠급니다
- **Ashfield 계정**: 웹과 같은 계정으로 로그인합니다

Windows 와 Linux 에서 동작하며, 실행 중인 [Ashfield Drive](https://github.com/ashfieldlab/ashfield-drive) 서버가 필요합니다.

## 시작하기

Node.js, Rust, OS 별 Tauri 준비물이 필요합니다 ([Tauri 준비물](https://tauri.app/start/prerequisites/), [Linux](docs/linux.md)).

```bash
cp .env.example .env
npm install
npm run tauri dev
```

## 문서

- [설정과 로그인](docs/configuration.md): 환경 변수, 로그인 방식
- [릴리스](RELEASE.md): 업데이트 서명 키, 빌드, GitHub Releases 배포
- [설계 노트](DESIGN.html)

## Ashfield

| | |
|---|---|
| [Account](https://github.com/ashfieldlab/ashfield-account) | 계정, 워크스페이스 |
| [Calendar](https://github.com/ashfieldlab/ashfield-calendar) | 일정, 회의실, 예약 |
| [Drive](https://github.com/ashfieldlab/ashfield-drive) | 파일 저장, 공유 |
| [Sync](https://github.com/ashfieldlab/ashfield-sync) | Drive 데스크톱 동기화 (Windows, Linux) |

## 라이선스

MIT
