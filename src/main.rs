#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod backup;
mod config;
mod ssh;
mod telnet;
mod term;
mod totp;
mod vault;
mod vendor;
mod vterm;

use std::io::Write;

fn options(renderer: eframe::Renderer) -> eframe::NativeOptions {
    eframe::NativeOptions {
        renderer,
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Switch SSH Console")
            .with_inner_size([1280.0, 780.0])
            .with_min_inner_size([900.0, 550.0]),
        ..Default::default()
    }
}

fn launch(renderer: eframe::Renderer) -> eframe::Result {
    eframe::run_native(
        "Switch SSH Console",
        options(renderer),
        Box::new(|cc| Ok(Box::new(app::SwitchApp::new(cc)))),
    )
}

/// wgpu aceitando renderizador por software (DirectX 12 WARP / llvmpipe).
/// Necessário em RDP, VMs e máquinas sem driver de GPU.
fn launch_software() -> eframe::Result {
    use eframe::egui_wgpu::{WgpuConfiguration, WgpuSetup, WgpuSetupCreateNew};
    use eframe::wgpu;
    use std::sync::Arc;

    let mut opts = options(eframe::Renderer::Wgpu);
    let mut setup = WgpuSetupCreateNew::default();
    setup.instance_descriptor.backends = wgpu::Backends::all();
    setup.native_adapter_selector = Some(Arc::new(|adapters, surface| {
        let usable: Vec<&wgpu::Adapter> = adapters
            .iter()
            .filter(|a| surface.is_none_or(|s| a.is_surface_supported(s)))
            .collect();
        // prefere GPU real; senão aceita CPU (WARP)
        usable
            .iter()
            .find(|a| a.get_info().device_type != wgpu::DeviceType::Cpu)
            .or_else(|| usable.first())
            .map(|a| (*a).clone())
            .ok_or_else(|| {
                let names: Vec<String> = adapters
                    .iter()
                    .map(|a| format!("{} ({:?})", a.get_info().name, a.get_info().backend))
                    .collect();
                format!("nenhum adaptador compatível; encontrados: {names:?}")
            })
    }));
    opts.wgpu_options = WgpuConfiguration {
        wgpu_setup: WgpuSetup::CreateNew(setup),
        ..Default::default()
    };
    eframe::run_native(
        "Switch SSH Console",
        opts,
        Box::new(|cc| Ok(Box::new(app::SwitchApp::new(cc)))),
    )
}

/// Grava erros de inicialização em %APPDATA%\switch-ssh-gui\erro.log
/// (no release o console fica oculto).
fn log_error(msg: &str) {
    let path = config::config_path().with_file_name("erro.log");
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "[{}] {msg}", chrono::Local::now().format("%d/%m/%Y %H:%M:%S"));
    }
    eprintln!("{msg}");
}

fn main() {
    std::panic::set_hook(Box::new(|info| log_error(&format!("PANIC: {info}"))));

    // Mesa (opengl32.dll ao lado do .exe): força o rasterizador llvmpipe.
    if std::env::var_os("GALLIUM_DRIVER").is_none() {
        std::env::set_var("GALLIUM_DRIVER", "llvmpipe");
    }

    // SWITCH_SSH_RENDERER=wgpu      -> pula OpenGL
    // SWITCH_SSH_RENDERER=software  -> vai direto para renderização por software
    let mode = std::env::var("SWITCH_SSH_RENDERER").unwrap_or_default().to_lowercase();
    if mode == "software" {
        if let Err(e) = launch_software() {
            log_error(&format!("Renderização por software falhou: {e}"));
            std::process::exit(1);
        }
        return;
    }
    let force_wgpu = mode == "wgpu";

    if !force_wgpu {
        match launch(eframe::Renderer::Glow) {
            Ok(()) => return,
            Err(e) => log_error(&format!("OpenGL falhou ({e}); tentando wgpu (DirectX/Vulkan)…")),
        }
    }
    match launch(eframe::Renderer::Wgpu) {
        Ok(()) => return,
        Err(e) => log_error(&format!("wgpu (GPU) falhou ({e}); tentando renderização por software (WARP)…")),
    }
    if let Err(e) = launch_software() {
        log_error(&format!("Renderização por software também falhou: {e}"));
        std::process::exit(1);
    }
}
