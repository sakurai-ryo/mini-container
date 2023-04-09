use nix::mount::{mount, MsFlags};
use nix::sched::{clone, CloneFlags};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chdir, chroot, execve, getpid, sethostname};
use std::env;
use std::ffi::CString;
use std::fs::{create_dir_all, write};
use std::path::PathBuf;

const ROOT_DIR: &str = "./root";

fn setup_child_process() -> Result<(), nix::errno::Errno> {
    mount::<str, str, str, str>(None, "/", None, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None)?; // マウントプロパゲーションの無効化
    chroot(ROOT_DIR)?; // プロセスのRootディレクトリを変更
    chdir("/")?; // 変更したRootディレクトリに移動
    mount::<str, str, str, str>(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_RELATIME | MsFlags::MS_RDONLY,
        None,
    )?; // procfsのマウント。manにある通り、sourceは`proc`文字列にする
    sethostname("container")?; // hostnameを変更する
    Ok(())
}

fn setup_cgroup() {
    // cgorup（今回はcgroup namespaceは利用しないので、ホスト側に作成される）
    let cgroup_path = &PathBuf::from("/sys/fs/cgroup/container");
    create_dir_all(cgroup_path).unwrap();
    write(
        cgroup_path.join("cgroup.procs"),
        getpid().as_raw().to_string(),
    )
    .unwrap(); // プロセスIDの書き込み、cgroupを適用する
    write(cgroup_path.join("memory.max"), "50M").unwrap(); // メモリのハードリミットを50Mに設定する
}

fn container_process(args: Vec<String>) -> isize {
    let command = args[1].clone();
    let args = &args[2..];
    let cstr_command = CString::new(command).unwrap_or_else(|_| CString::new("default").unwrap());
    let cstr_args: Vec<CString> = args
        .iter()
        .map(|arg| CString::new(arg.as_str()).unwrap_or_else(|_| CString::new("default").unwrap()))
        .collect();

    setup_cgroup();

    if let Err(e) = setup_child_process() {
        return e as isize;
    }
    if let Err(e) = execve::<CString, CString>(&cstr_command, &cstr_args, &[]) {
        eprint!("Execve error: {:?}", e);
        return e as isize;
    }
    0
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Invalida arguments");
        return;
    }

    let mut stack = vec![0; 1024 * 1024];
    let clone_flags = CloneFlags::CLONE_NEWUTS // UTS namespace
    | CloneFlags::CLONE_NEWPID // PID namespace
    | CloneFlags::CLONE_NEWNS // mount namespace
    | CloneFlags::CLONE_NEWIPC // IPC namespace
    | CloneFlags::CLONE_NEWNET; // network namespace
    match clone(
        Box::new(|| container_process(args.clone())),
        &mut stack,
        clone_flags,
        Some(Signal::SIGCHLD as i32),
    ) {
        Ok(pid) => {
            println!("Created Container with PID: {}", pid);
            match waitpid(pid, None) {
                Ok(status) => match status {
                    // https://github.com/nix-rust/nix/blob/1bfbb034cba446a370ba3c899a235b94fbcc2099/src/sys/wait.rs#L88
                    WaitStatus::Exited(_, status) => {
                        println!("Container process exited: {:?}", status)
                    }
                    WaitStatus::Signaled(_, status, _) => {
                        println!("Container process killed by signal: {:?}", status)
                    }
                    _ => eprintln!("Unexpected WaitStatus"),
                },
                Err(e) => eprintln!("Error waiting for child process: {:?}", e),
            }
        }
        Err(e) => {
            eprintln!("Error creating new process: {:?}", e);
        }
    }
}
