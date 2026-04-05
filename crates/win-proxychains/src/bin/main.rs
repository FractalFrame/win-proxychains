// Copyright (c) 2026 Fractal Frame <https://fractalframe.eu>
// Part of the win-proxychains project. Licensed under FSL-1.1-MIT; see LICENCE.md.

use std::{
    ffi::CString,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, ensure};
use clap::{ArgAction, Args, Parser};
use magpie_process::MemorySection;
use win_proxychains_dll::{
    InitializePacket,
    config::{ProxychainsConfig, SAMPLE_PROXYCHAINS_CONFIG},
    map_pe::{custom_get_proc_address, map_and_load_pe},
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, LoadLibraryA};

const DEBUG_MODE: &str = "debug";
const DEFAULT_CONFIG_NAME: &str = "proxychains.conf";
const CONFIG_ENV_VAR: &str = "WIN_PROXYCHAINS_CONFIG";
const INITIALIZE_SUCCESS: u32 = 1;
const DLL_CANDIDATE_NAMES: [&str; 2] = ["win_proxychains_dll.dll", "win_proxychains.dll"];
const CLI_ABOUT: &str = "Windows proxychains-style launcher from the win-proxychains project.";
const CLI_NOTICE: &str =
    "Part of the win-proxychains project by Fractal Frame (https://fractalframe.eu). Licensed under FSL-1.1-MIT; see LICENCE.md.";
const DEBUG_AFTER_HELP: &str =
    "Debug mode accepts debug-only flags before <program>.\n\nPart of the win-proxychains project by Fractal Frame (https://fractalframe.eu). Licensed under FSL-1.1-MIT; see LICENCE.md.";

fn main() {
    match run() {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(error) => {
            eprintln!("{error:#}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32> {
    let cli = Cli::parse();

    if cli.debug.dump_cli {
        eprintln!("{cli:#?}");
    }

    if let Some(path) = &cli.write_config {
        write_sample_config(path)?;
        return Ok(0);
    }

    match cli.mode {
        Mode::Debug => run_debug_mode(&cli).map(|_| 0),
        Mode::Proxychains => run_proxychains_mode(&cli),
    }
}

fn run_debug_mode(cli: &Cli) -> Result<()> {
    if let Some(path) = &cli.debug.load_pe {
        println!("Press Enter to continue... to stage 1");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        let (image_base, mapped_section) = load_pe_in_current_process(path)?;
        println!(
            "Loaded PE into current process: {} at: {:p}",
            path.display(),
            image_base as *const u8
        );

        println!("Mapped section: {}", mapped_section.name());

        println!("Press Enter to continue... to stage 2");
        input = String::new();
        std::io::stdin().read_line(&mut input)?;

        let initialize = custom_get_proc_address(image_base as *const _, "initialize_remote")
            .map(|address| address as *const ())
            .map_err(|_| anyhow!("Failed to find 'initialize_remote' function in the loaded PE"))?;

        println!("Press Enter to call initialize_remote at: {:p}", initialize);
        input.clear();
        std::io::stdin().read_line(&mut input)?;

        let initialize_result = initialize_mapped_proxychains(
            image_base,
            mapped_section.name(),
            SAMPLE_PROXYCHAINS_CONFIG,
        )?;
        println!("initialize_remote returned: {initialize_result}");

        println!("Press Enter to continue... to stage 3");
        input.clear();
        std::io::stdin().read_line(&mut input)?;

        let mut notepad = std::process::Command::new("notepad.exe")
            .spawn()
            .context("Failed to launch notepad.exe")?;

        println!("Press Enter to exit... to stage 4");
        input.clear();
        std::io::stdin().read_line(&mut input)?;

        notepad.kill().context("Failed to kill notepad.exe")?;
    }

    Ok(())
}

fn run_proxychains_mode(cli: &Cli) -> Result<i32> {
    let current_exe = current_exe_path()?;
    let config_path = resolve_config_path(cli.config.as_deref(), &current_exe)?;
    let raw_config = std::fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read config file {}", config_path.display()))?;
    let parsed_config = ProxychainsConfig::parse(&raw_config)
        .with_context(|| format!("failed to parse config file {}", config_path.display()))?;
    let normalized_config = parsed_config.to_string();

    let dll_path = resolve_proxychains_dll_path(&current_exe)?;
    let (image_base, mapped_section) = load_pe_in_current_process(&dll_path)?;
    let initialize_result =
        initialize_mapped_proxychains(image_base, mapped_section.name(), &normalized_config)?;
    ensure!(
        initialize_result == INITIALIZE_SUCCESS,
        "{}",
        initialize_failure_message(image_base, initialize_result)
    );

    let program = cli
        .program
        .as_ref()
        .context("proxychains mode requires a program to launch")?;
    let status = std::process::Command::new(program)
        .args(&cli.args)
        .status()
        .with_context(|| format!("failed to launch {}", program.to_string_lossy()))?;

    Ok(status.code().unwrap_or(1))
}

fn current_exe_path() -> Result<PathBuf> {
    std::env::current_exe().context("failed to determine current executable path")
}

fn resolve_proxychains_dll_path(current_exe: &Path) -> Result<PathBuf> {
    let exe_dir = current_exe.parent().ok_or_else(|| {
        anyhow!(
            "failed to determine the directory containing {}",
            current_exe.display()
        )
    })?;

    for candidate_name in DLL_CANDIDATE_NAMES {
        let candidate = exe_dir.join(candidate_name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    anyhow::bail!(
        "failed to find proxychains DLL next to {}; tried {}",
        current_exe.display(),
        DLL_CANDIDATE_NAMES.join(", ")
    )
}

fn resolve_config_path(config: Option<&Path>, current_exe: &Path) -> Result<PathBuf> {
    if let Some(path) = config {
        return Ok(path.to_path_buf());
    }

    if let Some(env_path) = std::env::var_os(CONFIG_ENV_VAR) {
        let env_path = PathBuf::from(env_path);
        if env_path.is_file() {
            return Ok(env_path);
        }

        anyhow::bail!(
            "config path from {} does not point to a readable file: {}",
            CONFIG_ENV_VAR,
            env_path.display()
        );
    }

    let cwd_candidate = PathBuf::from(DEFAULT_CONFIG_NAME);
    if cwd_candidate.is_file() {
        return Ok(cwd_candidate);
    }

    let exe_dir = current_exe.parent().ok_or_else(|| {
        anyhow!(
            "failed to determine the directory containing {}",
            current_exe.display()
        )
    })?;
    let exe_dir_candidate = exe_dir.join(DEFAULT_CONFIG_NAME);
    if exe_dir_candidate.is_file() {
        return Ok(exe_dir_candidate);
    }

    anyhow::bail!(
        "no config file provided; tried {} from {}, in the current directory, and next to {}",
        DEFAULT_CONFIG_NAME,
        CONFIG_ENV_VAR,
        current_exe.display()
    )
}

fn write_sample_config(path: &Path) -> Result<()> {
    std::fs::write(path, SAMPLE_PROXYCHAINS_CONFIG)
        .with_context(|| format!("failed to write sample config to {}", path.display()))
}

fn initialize_mapped_proxychains(image_base: u64, section_name: &str, config: &str) -> Result<u32> {
    let initialize = custom_get_proc_address(image_base as *const _, "initialize_remote")
        .map_err(|_| anyhow!("Failed to find 'initialize_remote' function in the loaded PE"))?;
    let initialize: unsafe extern "C" fn(*const InitializePacket) -> u32 =
        unsafe { std::mem::transmute(initialize) };
    let config_packet = InitializePacket::new(config, section_name, image_base)?;

    Ok(unsafe { initialize(&config_packet as *const _) })
}

fn initialize_failure_message(image_base: u64, status: u32) -> String {
    let get_last_error_size =
        match custom_get_proc_address(image_base as *const _, "get_last_error_size") {
            Ok(address) => unsafe {
                std::mem::transmute::<_, unsafe extern "C" fn() -> usize>(address)
            },
            Err(_) => return format!("initialize_remote failed with status {status}"),
        };

    let get_last_error_message =
        match custom_get_proc_address(image_base as *const _, "get_last_error_message") {
            Ok(address) => unsafe {
                std::mem::transmute::<_, unsafe extern "C" fn(*mut u8, usize) -> usize>(address)
            },
            Err(_) => return format!("initialize_remote failed with status {status}"),
        };

    let size = unsafe { get_last_error_size() };
    if size == 0 {
        return format!("initialize_remote failed with status {status}");
    }

    let mut buffer = vec![0u8; size];
    let copied = unsafe { get_last_error_message(buffer.as_mut_ptr(), buffer.len()) };
    buffer.truncate(copied);
    let message = String::from_utf8_lossy(&buffer);

    format!("initialize_remote failed with status {status}: {message}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    Proxychains,
    Debug,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Args)]
struct DebugOptions {
    #[arg(
        long,
        action = ArgAction::SetTrue,
        help = "Print the parsed CLI in debug mode and exit"
    )]
    dump_cli: bool,

    #[arg(
        long,
        value_name = "path",
        help = "Map and load a PE into the current process"
    )]
    load_pe: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
struct ProxychainsOptions {
    #[arg(short = 'q', action = ArgAction::SetTrue, help = "Quiet mode")]
    quiet: bool,

    #[arg(
        short = 'c',
        value_name = "config_path",
        help = "Write the documented sample config to the given path and exit"
    )]
    write_config: Option<PathBuf>,

    #[arg(
        short = 'f',
        value_name = "configfile.conf",
        help = "Use the given config file (otherwise checks WIN_PROXYCHAINS_CONFIG)"
    )]
    config: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
struct RequiredCommandToRun {
    #[arg(value_name = "program", required = true)]
    program: OsString,

    #[arg(
        value_name = "arguments",
        allow_hyphen_values = true,
        trailing_var_arg = true
    )]
    args: Vec<OsString>,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
struct OptionalCommandToRun {
    #[arg(value_name = "program")]
    program: Option<OsString>,

    #[arg(
        value_name = "arguments",
        allow_hyphen_values = true,
        trailing_var_arg = true
    )]
    args: Vec<OsString>,
}

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
#[command(
    name = "proxychains4",
    about = CLI_ABOUT,
    disable_version_flag = true,
    arg_required_else_help = true,
    after_help = CLI_NOTICE
)]
struct ProxychainsCli {
    #[command(flatten)]
    options: ProxychainsOptions,

    #[command(flatten)]
    command: OptionalCommandToRun,
}

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
#[command(
    name = "proxychains4 debug",
    about = "Debug utilities for the win-proxychains launcher.",
    disable_version_flag = true,
    arg_required_else_help = true,
    after_help = DEBUG_AFTER_HELP
)]
struct DebugCli {
    #[command(flatten)]
    options: ProxychainsOptions,

    #[command(flatten, next_help_heading = "Debug Options")]
    debug: DebugOptions,

    #[command(flatten)]
    command: OptionalCommandToRun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cli {
    mode: Mode,
    quiet: bool,
    write_config: Option<PathBuf>,
    config: Option<PathBuf>,
    program: Option<OsString>,
    args: Vec<OsString>,
    debug: DebugOptions,
}

impl Cli {
    fn parse() -> Self {
        Self::try_parse_from(std::env::args_os()).unwrap_or_else(|error| error.exit())
    }

    fn try_parse_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        let raw_args: Vec<OsString> = args.into_iter().map(Into::into).collect();

        if matches!(raw_args.get(1), Some(mode) if mode == OsStr::new(DEBUG_MODE)) {
            let debug_args = std::iter::once(raw_args[0].clone())
                .chain(raw_args.iter().skip(2).cloned())
                .collect::<Vec<_>>();
            let parsed = DebugCli::try_parse_from(debug_args)?;

            Ok(Self {
                mode: Mode::Debug,
                quiet: parsed.options.quiet,
                write_config: parsed.options.write_config,
                config: parsed.options.config,
                program: parsed.command.program,
                args: parsed.command.args,
                debug: parsed.debug,
            })
        } else {
            let parsed = ProxychainsCli::try_parse_from(raw_args)?;
            if parsed.options.write_config.is_none() && parsed.command.program.is_none() {
                return Err(clap::Error::raw(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "proxychains mode requires a program to launch",
                ));
            }

            Ok(Self {
                mode: Mode::Proxychains,
                quiet: parsed.options.quiet,
                write_config: parsed.options.write_config,
                config: parsed.options.config,
                program: parsed.command.program,
                args: parsed.command.args,
                debug: DebugOptions::default(),
            })
        }
    }
}

fn load_pe_in_current_process(path: &Path) -> Result<(u64, MemorySection)> {
    let winsock_name =
        CString::new("ws2_32.dll").expect("CString::new on a string literal should not fail");
    let winsock_module = unsafe { LoadLibraryA(winsock_name.as_ptr() as *const u8) };

    if winsock_module.is_null() {
        anyhow::bail!("failed to load ws2_32.dll");
    }

    let winsock_module = winsock_module as u64;

    let dns_api_name =
        CString::new("dnsapi.dll").expect("CString::new on a string literal should not fail");
    let dns_api_module = unsafe { LoadLibraryA(dns_api_name.as_ptr() as *const u8) };

    if dns_api_module.is_null() {
        anyhow::bail!("failed to load dnsapi.dll");
    }

    let dns_api_module = dns_api_module as u64;

    let ntdll_name =
        CString::new("ntdll.dll").expect("CString::new on a string literal should not fail");
    let ntdll_module = unsafe { GetModuleHandleA(ntdll_name.as_ptr() as *const u8) } as u64;

    map_and_load_pe(path, &[ntdll_module, winsock_module, dns_api_module])
        .with_context(|| format!("failed to map PE into current process: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::{
        Cli, CONFIG_ENV_VAR, Mode, resolve_config_path, resolve_proxychains_dll_path,
        write_sample_config,
    };
    use std::{
        ffi::OsString,
        fs,
        path::Path,
        path::PathBuf,
        sync::{Mutex, OnceLock},
        time::{SystemTime, UNIX_EPOCH},
    };
    use win_proxychains_dll::config::SAMPLE_PROXYCHAINS_CONFIG;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn write_test_config(path: &Path) {
        fs::write(path, "strict_chain\n[ProxyList]\nsocks5 127.0.0.1 1080\n")
            .expect("config placeholder should be written");
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("win-proxychains-{name}-{suffix}"))
    }

    #[test]
    fn parses_proxychains_mode_like_proxychains4() {
        let cli = Cli::try_parse_from([
            "win-proxychains",
            "-q",
            "-f",
            "proxychains.conf",
            "curl",
            "--silent",
            "https://example.com",
        ])
        .expect("proxychains mode should parse");

        assert_eq!(cli.mode, Mode::Proxychains);
        assert!(cli.quiet);
        assert_eq!(cli.write_config, None);
        assert_eq!(cli.config, Some("proxychains.conf".into()));
        assert_eq!(cli.program, Some(OsString::from("curl")));
        assert_eq!(
            cli.args,
            vec![
                OsString::from("--silent"),
                OsString::from("https://example.com")
            ]
        );
        assert!(!cli.debug.dump_cli);
    }

    #[test]
    fn parses_debug_mode_with_debug_only_flags() {
        let cli = Cli::try_parse_from([
            "win-proxychains",
            "debug",
            "--dump-cli",
            "--load-pe",
            "my-hook.dll",
            "-f",
            "proxychains.conf",
            "curl",
            "--silent",
        ])
        .expect("debug mode should parse");

        assert_eq!(cli.mode, Mode::Debug);
        assert!(cli.debug.dump_cli);
        assert_eq!(cli.write_config, None);
        assert_eq!(cli.debug.load_pe, Some("my-hook.dll".into()));
        assert_eq!(cli.program, Some(OsString::from("curl")));
        assert_eq!(cli.args, vec![OsString::from("--silent")]);
    }

    #[test]
    fn rejects_debug_only_flags_outside_debug_mode() {
        let error = Cli::try_parse_from(["win-proxychains", "--dump-cli", "curl"])
            .expect_err("non-debug mode must stay strict");

        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn parses_write_config_without_program() {
        let cli = Cli::try_parse_from(["win-proxychains", "-c", "generated.conf"])
            .expect("write-config mode should parse without a command");

        assert_eq!(cli.mode, Mode::Proxychains);
        assert_eq!(cli.write_config, Some("generated.conf".into()));
        assert_eq!(cli.program, None);
        assert!(cli.args.is_empty());
    }

    #[test]
    fn rejects_proxychains_mode_without_program_or_write_config() {
        let error = Cli::try_parse_from(["win-proxychains"])
            .expect_err("non-debug mode should require a command or -c");

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }

    #[test]
    fn parses_debug_mode_with_only_load_pe() {
        let cli = Cli::try_parse_from(["win-proxychains", "debug", "--load-pe", "my-hook.dll"])
            .expect("debug mode should allow load-pe without a command");

        assert_eq!(cli.mode, Mode::Debug);
        assert_eq!(cli.debug.load_pe, Some("my-hook.dll".into()));
        assert_eq!(cli.write_config, None);
        assert_eq!(cli.program, None);
        assert!(cli.args.is_empty());
    }

    #[test]
    fn resolves_proxychains_dll_next_to_executable() {
        let temp_dir = unique_temp_dir("dll");
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");

        let exe_path = temp_dir.join("win-proxychains.exe");
        fs::write(&exe_path, b"").expect("launcher placeholder should be written");

        let dll_path = temp_dir.join("win_proxychains_dll.dll");
        fs::write(&dll_path, b"").expect("dll placeholder should be written");

        let resolved = resolve_proxychains_dll_path(&exe_path)
            .expect("sibling proxychains dll should resolve");
        assert_eq!(resolved, dll_path);

        fs::remove_dir_all(&temp_dir).expect("temp dir should be cleaned up");
    }

    #[test]
    fn resolve_config_path_returns_explicit_path_without_searching() {
        let _env_guard = env_lock().lock().expect("env lock should not be poisoned");
        let temp_dir = unique_temp_dir("config");
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");

        let exe_path = temp_dir.join("win-proxychains.exe");
        let config_path = temp_dir.join("custom.conf");
        write_test_config(&config_path);

        let resolved = resolve_config_path(Some(config_path.as_path()), &exe_path)
            .expect("explicit config path should be returned");
        assert_eq!(resolved, config_path);

        fs::remove_dir_all(&temp_dir).expect("temp dir should be cleaned up");
    }

    #[test]
    fn resolve_config_path_uses_env_var_when_cli_path_is_missing() {
        let _env_guard = env_lock().lock().expect("env lock should not be poisoned");
        let temp_dir = unique_temp_dir("config-env");
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");

        let exe_path = temp_dir.join("win-proxychains.exe");
        let env_config_path = temp_dir.join("env.conf");
        write_test_config(&env_config_path);

        unsafe {
            std::env::set_var(CONFIG_ENV_VAR, &env_config_path);
        }

        let resolved =
            resolve_config_path(None, &exe_path).expect("env config path should be returned");
        assert_eq!(resolved, env_config_path);

        unsafe {
            std::env::remove_var(CONFIG_ENV_VAR);
        }
        fs::remove_dir_all(&temp_dir).expect("temp dir should be cleaned up");
    }

    #[test]
    fn resolve_config_path_prefers_cli_path_over_env_var() {
        let _env_guard = env_lock().lock().expect("env lock should not be poisoned");
        let temp_dir = unique_temp_dir("config-cli-over-env");
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");

        let exe_path = temp_dir.join("win-proxychains.exe");
        let cli_config_path = temp_dir.join("cli.conf");
        let env_config_path = temp_dir.join("env.conf");
        write_test_config(&cli_config_path);
        write_test_config(&env_config_path);

        unsafe {
            std::env::set_var(CONFIG_ENV_VAR, &env_config_path);
        }

        let resolved = resolve_config_path(Some(cli_config_path.as_path()), &exe_path)
            .expect("cli config path should take precedence");
        assert_eq!(resolved, cli_config_path);

        unsafe {
            std::env::remove_var(CONFIG_ENV_VAR);
        }
        fs::remove_dir_all(&temp_dir).expect("temp dir should be cleaned up");
    }

    #[test]
    fn resolve_config_path_errors_when_env_var_points_to_missing_file() {
        let _env_guard = env_lock().lock().expect("env lock should not be poisoned");
        let temp_dir = unique_temp_dir("config-env-missing");
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");

        let exe_path = temp_dir.join("win-proxychains.exe");
        let missing_path = temp_dir.join("missing.conf");

        unsafe {
            std::env::set_var(CONFIG_ENV_VAR, &missing_path);
        }

        let error = resolve_config_path(None, &exe_path)
            .expect_err("missing env config path should be rejected");
        assert!(
            error
                .to_string()
                .contains("config path from WIN_PROXYCHAINS_CONFIG does not point to a readable file"),
            "unexpected error: {error:#}"
        );

        unsafe {
            std::env::remove_var(CONFIG_ENV_VAR);
        }
        fs::remove_dir_all(&temp_dir).expect("temp dir should be cleaned up");
    }

    #[test]
    fn write_sample_config_persists_documented_template() {
        let temp_dir = unique_temp_dir("write-config");
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");

        let config_path = temp_dir.join("generated.conf");
        write_sample_config(&config_path).expect("sample config should be written");

        let written = fs::read_to_string(&config_path).expect("written config should be readable");
        assert_eq!(written, SAMPLE_PROXYCHAINS_CONFIG);

        fs::remove_dir_all(&temp_dir).expect("temp dir should be cleaned up");
    }
}
