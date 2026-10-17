//! Windows: a Service Control Manager service that starts automatically and is restarted
//! on failure. It runs under its own virtual account (`NT SERVICE\localname`), which has
//! no password and only the rights granted here: modify access to the configuration
//! directory. The binary is copied to Program Files, which only administrators can write.

use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use tokio::sync::watch;
use windows_service::{
    define_windows_service,
    service::{
        Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceControl,
        ServiceControlAccept, ServiceDependency, ServiceErrorControl, ServiceExitCode,
        ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceSidType,
        ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

use super::{DaemonState, remove_file, replace_file, same_contents};
use crate::{
    ConfigStore,
    client::{MARKER, run},
    error::{ErrorCode, coded},
};

const NAME: &str = "localname";
const DISPLAY: &str = "localname LAN DNS";
const ACCOUNT: &str = r"NT SERVICE\localname";
/// Logs larger than this are rotated to `daemon.log.old` when the service starts.
const LOG_LIMIT: u64 = 1 << 20;

fn program_files() -> PathBuf {
    env::var_os("ProgramFiles").map_or_else(|| PathBuf::from(r"C:\Program Files"), PathBuf::from)
}

fn program_data() -> PathBuf {
    env::var_os("ProgramData").map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
}

fn binary_path() -> PathBuf {
    program_files().join("localname").join("localname.exe")
}

fn data_directory() -> PathBuf {
    program_data().join("localname")
}

pub fn config_path() -> PathBuf {
    data_directory().join("config.toml")
}

fn log_path() -> PathBuf {
    data_directory().join("daemon.log")
}

fn description() -> String {
    format!(
        "{MARKER}: names for devices on this network. Remove with `localname daemon uninstall`."
    )
}

/// Map Service Control Manager errors to stable codes.
fn scm(error: &windows_service::Error, action: &str) -> anyhow::Error {
    match error {
        windows_service::Error::Winapi(io) if io.raw_os_error() == Some(5) => coded(
            ErrorCode::PermissionRequired,
            format!("permission required: {action} requires an administrator PowerShell ({io})"),
        ),
        windows_service::Error::Winapi(io) => anyhow!("failed to {action}: {io}"),
        _ => anyhow!("failed to {action}: {error}"),
    }
}

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access)
        .map_err(|error| scm(&error, "open the Service Control Manager"))
}

fn open(manager: &ServiceManager, access: ServiceAccess) -> Result<Option<Service>> {
    match manager.open_service(NAME, access) {
        Ok(service) => Ok(Some(service)),
        Err(windows_service::Error::Winapi(io)) if io.raw_os_error() == Some(1060) => Ok(None),
        Err(error) => Err(scm(&error, "open the localname service")),
    }
}

/// The executable in a service command line, which may be quoted and carry arguments.
fn executable(command: &Path) -> PathBuf {
    let text = command.to_string_lossy();
    let text = text.trim();
    if let Some(rest) = text.strip_prefix('"') {
        return PathBuf::from(rest.split('"').next().unwrap_or(rest));
    }
    let lowered = text.to_ascii_lowercase();
    lowered.find(".exe").map_or_else(
        || PathBuf::from(text),
        |end| PathBuf::from(&text[..end + 4]),
    )
}

pub fn detect() -> Result<DaemonState> {
    let mut state = DaemonState {
        manager: "windows-scm",
        unsupported: None,
        service: NAME.into(),
        definition: format!("Windows service {NAME}"),
        installed: false,
        managed: false,
        enabled: false,
        running: false,
        pid: None,
        binary: binary_path(),
        config: config_path(),
        account: ACCOUNT.into(),
        log: log_path().to_string_lossy().into_owned(),
        conflicts: Vec::new(),
    };
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let Some(service) = open(
        &manager,
        ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
    )?
    else {
        return Ok(state);
    };
    let config = service
        .query_config()
        .map_err(|error| scm(&error, "read the localname service"))?;
    let binary = executable(&config.executable_path);
    if config.display_name != OsStr::new(DISPLAY) || !binary.eq(&binary_path()) {
        state.conflicts.push(format!(
            "a Windows service named {NAME} exists ({}) and was not installed by localname",
            binary.display()
        ));
        return Ok(state);
    }
    state.installed = true;
    state.managed = true;
    state.enabled = matches!(config.start_type, ServiceStartType::AutoStart);
    let status = service
        .query_status()
        .map_err(|error| scm(&error, "read the localname service status"))?;
    state.running = matches!(
        status.current_state,
        ServiceState::Running | ServiceState::StartPending
    );
    state.pid = status.process_id.filter(|pid| *pid != 0);
    Ok(state)
}

pub fn plan_install(state: &DaemonState, source: &Path) -> Vec<String> {
    let binary = binary_path();
    let mut steps = Vec::new();
    if !same_contents(source, &binary) {
        if state.running {
            steps.push(format!("Stop the {NAME} service to replace its binary."));
        }
        steps.push(format!(
            "Copy {} to {}.",
            source.display(),
            binary.display()
        ));
    }
    steps.push(format!(
        "{} the {NAME} service: automatic start, restart on failure, account {ACCOUNT}.",
        if state.installed { "Update" } else { "Create" }
    ));
    steps.push(format!(
        "Give only SYSTEM, Administrators, and {ACCOUNT} access to {}.",
        data_directory().display()
    ));
    steps.push(format!("Start the {NAME} service."));
    steps
}

fn service_info() -> ServiceInfo {
    ServiceInfo {
        name: NAME.into(),
        display_name: DISPLAY.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: binary_path(),
        launch_arguments: vec![
            "--config".into(),
            config_path().into_os_string(),
            "daemon".into(),
            "run".into(),
        ],
        dependencies: vec![ServiceDependency::Service("Tcpip".into())],
        account_name: Some(ACCOUNT.into()),
        account_password: None,
    }
}

fn wait_for(service: &Service, wanted: ServiceState) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status = service
            .query_status()
            .map_err(|error| scm(&error, "read the localname service status"))?;
        if status.current_state == wanted {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(coded(
                ErrorCode::Unavailable,
                format!(
                    "the localname service did not reach {wanted:?} within 30 s (unavailable); see {}",
                    log_path().display()
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn stop_and_wait(service: &Service) -> Result<()> {
    let status = service
        .query_status()
        .map_err(|error| scm(&error, "read the localname service status"))?;
    if status.current_state == ServiceState::Stopped {
        return Ok(());
    }
    if status.current_state != ServiceState::StopPending {
        service
            .stop()
            .map_err(|error| scm(&error, "stop the localname service"))?;
    }
    wait_for(service, ServiceState::Stopped)
}

fn start_and_wait(service: &Service) -> Result<()> {
    let status = service
        .query_status()
        .map_err(|error| scm(&error, "read the localname service status"))?;
    if status.current_state != ServiceState::Running {
        if status.current_state != ServiceState::StartPending {
            service
                .start::<&OsStr>(&[])
                .map_err(|error| scm(&error, "start the localname service"))?;
        }
        wait_for(service, ServiceState::Running)?;
    }
    Ok(())
}

/// Only SYSTEM, Administrators, and the service account may use the data directory;
/// existing contents inherit that.
fn restrict_data_directory() -> Result<()> {
    let directory = data_directory();
    fs::create_dir_all(&directory)
        .with_context(|| format!("failed to create {}", directory.display()))?;
    let text = directory.to_string_lossy().into_owned();
    run(
        "icacls.exe",
        &[
            &text,
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            &format!("{ACCOUNT}:(OI)(CI)M"),
            "/Q",
        ],
    )?;
    if fs::read_dir(&directory)?.next().is_some() {
        run(
            "icacls.exe",
            &[&format!("{text}\\*"), "/reset", "/T", "/C", "/Q"],
        )?;
    }
    Ok(())
}

pub fn install(state: &DaemonState, source: &Path) -> Result<Vec<String>> {
    let mut steps = Vec::new();
    let manager = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let access = ServiceAccess::QUERY_CONFIG
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::STOP;
    let existing = open(&manager, access)?;
    let binary = binary_path();
    let replace = !same_contents(source, &binary);
    if replace {
        if let Some(service) = &existing {
            stop_and_wait(service)?;
            if state.running {
                steps.push(format!("Stopped the {NAME} service."));
            }
        }
        replace_file(&binary, &fs::read(source)?, 0o755)?;
        steps.push(format!(
            "Copied {} to {}.",
            source.display(),
            binary.display()
        ));
    }
    let info = service_info();
    let service = if let Some(service) = existing {
        service
            .change_config(&info)
            .map_err(|error| scm(&error, "update the localname service"))?;
        steps.push(format!("Updated the {NAME} service."));
        service
    } else {
        let service = manager
            .create_service(&info, access)
            .map_err(|error| scm(&error, "create the localname service"))?;
        steps.push(format!(
            "Created the {NAME} service (automatic start, account {ACCOUNT})."
        ));
        service
    };
    service
        .set_description(description())
        .map_err(|error| scm(&error, "describe the localname service"))?;
    service
        .set_config_service_sid_info(ServiceSidType::Unrestricted)
        .map_err(|error| scm(&error, "configure the localname service account"))?;
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
            reboot_msg: None,
            command: None,
            actions: Some(
                [5, 10, 30]
                    .map(|seconds| ServiceAction {
                        action_type: ServiceActionType::Restart,
                        delay: Duration::from_secs(seconds),
                    })
                    .to_vec(),
            ),
        })
        .map_err(|error| scm(&error, "set the localname service recovery actions"))?;
    service
        .set_failure_actions_on_non_crash_failures(true)
        .map_err(|error| scm(&error, "set the localname service recovery actions"))?;
    steps.push("Restarts after 5, 10, and 30 s when it fails.".into());
    restrict_data_directory()?;
    steps.push(format!(
        "Restricted {} to SYSTEM, Administrators, and {ACCOUNT}.",
        data_directory().display()
    ));
    start_and_wait(&service)?;
    steps.push(format!("Started the {NAME} service."));
    Ok(steps)
}

pub fn uninstall(_state: &DaemonState) -> Result<Vec<String>> {
    let mut steps = Vec::new();
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    if let Some(service) = open(
        &manager,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )? {
        stop_and_wait(&service)?;
        steps.push(format!("Stopped the {NAME} service."));
        service
            .delete()
            .map_err(|error| scm(&error, "remove the localname service"))?;
        steps.push(format!("Removed the {NAME} service."));
    }
    let binary = binary_path();
    let running_copy = env::current_exe()
        .ok()
        .and_then(|path| path.canonicalize().ok())
        .zip(binary.canonicalize().ok())
        .is_some_and(|(current, installed)| current == installed);
    if running_copy {
        steps.push(format!(
            "Kept {}, which is running this command; delete it afterwards.",
            binary.display()
        ));
    } else if remove_file(&binary)? {
        let _ = fs::remove_dir(binary.parent().unwrap_or(Path::new("C:\\")));
        steps.push(format!("Removed {}.", binary.display()));
    }
    steps.push(format!(
        "Kept the configuration in {}.",
        data_directory().display()
    ));
    Ok(steps)
}

pub fn start(_state: &DaemonState) -> Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let service = open(&manager, ServiceAccess::QUERY_STATUS | ServiceAccess::START)?
        .ok_or_else(|| anyhow!("the localname service is not installed (unavailable)"))?;
    start_and_wait(&service)
}

pub fn stop(_state: &DaemonState) -> Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let service = open(&manager, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)?
        .ok_or_else(|| anyhow!("the localname service is not installed (unavailable)"))?;
    stop_and_wait(&service)
}

// Service runtime: the Service Control Manager starts `localname.exe --config PATH daemon
// run`, which hands the main thread to the dispatcher.

static CONFIG: OnceLock<PathBuf> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Connect to the Service Control Manager and run the service until it is stopped.
pub fn run_dispatcher(config: PathBuf) -> Result<()> {
    let _ = CONFIG.set(config);
    service_dispatcher::start(NAME, ffi_service_main).map_err(|error| {
        coded(
            ErrorCode::InvalidInput,
            format!(
                "invalid use: `localname daemon run` is started by the Windows Service Control Manager; use `localname daemon start` ({error})"
            ),
        )
    })
}

fn service_main(_arguments: Vec<OsString>) {
    let config = CONFIG.get().cloned().unwrap_or_else(config_path);
    init_log();
    if let Err(error) = run_service(config) {
        tracing::error!("{error:#}");
    }
}

/// Log warnings and errors to `daemon.log` beside the configuration.
fn init_log() {
    let path = log_path();
    if fs::metadata(&path).is_ok_and(|metadata| metadata.len() > LOG_LIMIT) {
        let _ = fs::rename(&path, path.with_extension("log.old"));
    }
    let Ok(file) = fs::OpenOptions::new().create(true).append(true).open(&path) else {
        return;
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_target(false)
        .with_writer(Mutex::new(file))
        .try_init();
}

fn status(state: ServiceState, exit_code: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: if exit_code == 0 {
            ServiceExitCode::Win32(0)
        } else {
            ServiceExitCode::ServiceSpecific(exit_code)
        },
        checkpoint: 0,
        wait_hint: if state == ServiceState::Running {
            Duration::ZERO
        } else {
            Duration::from_secs(30)
        },
        process_id: None,
    }
}

fn run_service(config: PathBuf) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = service_control_handler::register(NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = shutdown_tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .map_err(|error| anyhow!("failed to register the service control handler: {error}"))?;
    let _ = handle.set_service_status(status(ServiceState::StartPending, 0));
    let result = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(
            std::thread::available_parallelism()
                .map_or(2, std::num::NonZero::get)
                .clamp(2, 4),
        )
        .enable_all()
        .build()
        .map_err(anyhow::Error::from)
        .and_then(|runtime| {
            runtime.block_on(crate::cli::serve_until(
                ConfigStore::new(config),
                None,
                shutdown_rx,
                || {
                    let _ = handle.set_service_status(status(ServiceState::Running, 0));
                },
            ))
        });
    if let Err(error) = &result {
        tracing::error!("localname service stopped: {error:#}");
        let _ = std::io::stderr().flush();
    }
    // A non-zero exit code counts as a failure, so the recovery actions restart it.
    let _ = handle.set_service_status(status(ServiceState::Stopped, u32::from(result.is_err())));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_command_lines_yield_the_executable() {
        assert_eq!(
            executable(Path::new(
                r#""C:\Program Files\localname\localname.exe" --config "C:\ProgramData\localname\config.toml" daemon run"#
            )),
            PathBuf::from(r"C:\Program Files\localname\localname.exe")
        );
        assert_eq!(
            executable(Path::new(r"C:\tools\other.exe -k netsvcs")),
            PathBuf::from(r"C:\tools\other.exe")
        );
    }

    #[test]
    fn the_service_runs_under_its_virtual_account() {
        let info = service_info();
        assert_eq!(info.account_name.as_deref(), Some(OsStr::new(ACCOUNT)));
        assert!(matches!(info.start_type, ServiceStartType::AutoStart));
        assert_eq!(info.launch_arguments.last().unwrap(), "run");
    }
}
