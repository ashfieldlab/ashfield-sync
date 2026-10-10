mod oauth;
mod sse;
mod vfs;
mod watcher;

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Manager, WindowEvent};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};

fn show_main(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .plugin(tauri_plugin_dialog::init())
        // 자동 시작 — Windows 시작 시 트레이로 조용히 (--minimized)
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ))
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            // 트레이 메뉴 — 열기 / 종료
            let show = MenuItem::with_id(app, "show", "Ashfield Sync 열기", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "종료", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;

            TrayIconBuilder::with_id("main-tray")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("Ashfield Sync")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => show_main(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    // 좌클릭 = 창 열기/포커스
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main(tray.app_handle());
                    }
                })
                .build(app)?;

            // 자동 시작 (idempotent). release 빌드만 등록 — debug 빌드는 UI 를
            // dev 서버(localhost)에서 불러오므로 부팅 시 자동 실행되면 dev 서버가
            // 없어 빈 화면(ERR_CONNECTION_REFUSED). debug 에선 오히려 해제해
            // 기존에 잘못 등록된 dev 자동시작도 정리한다.
            let autostart = app.autolaunch();
            #[cfg(debug_assertions)]
            let _ = autostart.disable();
            #[cfg(not(debug_assertions))]
            let _ = autostart.enable();
            if std::env::args().any(|a| a == "--minimized") {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.hide();
                }
            }
            Ok(())
        })
        // 창 닫기(✕) = 종료 대신 트레이로 숨김 (OneDrive 패턴 — 상주 유지).
        // 진짜 종료는 트레이 메뉴 '종료'.
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            oauth::oauth_login,
            oauth::oauth_refresh,
            oauth::oauth_logout,
            oauth::oauth_has_stored_refresh,
            vfs::vfs_register,
            vfs::vfs_unregister,
            vfs::vfs_populate,
            vfs::vfs_set_deks,
            vfs::vfs_encrypt_to_temp,
            vfs::vfs_delete,
            vfs::vfs_remove_dir,
            vfs::vfs_prune,
            vfs::vfs_connect,
            vfs::vfs_disconnect,
            vfs::vfs_file_size,
            vfs::vfs_file_stat,
            vfs::vfs_put_file,
            vfs::vfs_put_file_part,
            vfs::vfs_make_conflict_copy,
            watcher::watcher_start,
            watcher::watcher_stop,
            sse::sse_connect,
            sse::sse_disconnect,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
