use tokio::process::{Child, Command};

pub(crate) fn prepare_process_group(command: &mut Command) {
    command.kill_on_drop(true);

    #[cfg(unix)]
    command.process_group(0);

    #[cfg(windows)]
    command.creation_flags(CREATE_NEW_PROCESS_GROUP);
}

pub(crate) async fn terminate_process_group(child: &mut Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // The child was spawned with process_group(0), so its PID is also the PGID.
        unsafe {
            libc::kill(-(pid as i32), libc::SIGTERM);
        }
    }

    #[cfg(windows)]
    if let Some(pid) = child.id() {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .kill_on_drop(true)
            .output()
            .await;
    }

    let _ = child.start_kill();
    let _ = child.wait().await;
}

#[cfg(windows)]
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
