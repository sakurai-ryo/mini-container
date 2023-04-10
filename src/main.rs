use nix::errno::Errno;
use nix::mount::{mount, MsFlags};
use nix::sched::{clone, CloneFlags};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chdir, chroot, execve, getpid, sethostname};
use std::env;
use std::ffi::CString;
use std::fs::{create_dir_all, write};
use std::io;
use std::path::PathBuf;

const ROOT_DIR: &str = "./root";

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
    | CloneFlags::CLONE_NEWNET // network namespace
    | CloneFlags::CLONE_NEWCGROUP; // cgroup namespace
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

fn container_process(args: Vec<String>) -> isize {
    let command = args[1].clone();
    let args = &args[2..];
    let cstr_command = CString::new(command).unwrap_or_else(|_| CString::new("default").unwrap());
    let cstr_args: Vec<CString> = args
        .iter()
        .map(|arg| CString::new(arg.as_str()).unwrap_or_else(|_| CString::new("default").unwrap()))
        .collect();

    if let Err(e) = setup_child_process() {
        return e as isize;
    }
    if let Err(e) = execve::<CString, CString>(&cstr_command, &cstr_args, &[]) {
        return e as isize;
    }
    0
}

fn setup_child_process() -> Result<(), Errno> {
    // hostnameを変更する
    sethostname("container")?;

    // マウントプロパゲーションの無効化
    // runcの参考箇所: https://github.com/opencontainers/runc/blob/d8a3daacbd8e30b074047c060d2eeb4f48ffa1cf/libcontainer/rootfs_linux.go#L784
    // runcの参孝コミット: https://github.com/opencontainers/runc/commit/117c92745bd098bf05a69489b7b78cac6364e1d0
    mount::<str, str, str, str>(None, "/", None, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None)?;

    // プロセスのRootディレクトリを変更（簡易化のためpivot_rootは使わない）
    chroot(ROOT_DIR)?;
    // 変更したRootディレクトリに移動
    chdir("/")?;

    // procfsのマウント。man 8 mountにある通り、sourceは`proc`文字列にする
    // フラグの参考: https://github.com/opencontainers/runc/blob/main/libcontainer/SPEC.md#:~:text=Data-,/proc,-proc
    // runcが読むconfig.jsonのprocfsの箇所: https://github.com/opencontainers/runtime-spec/blob/main/config.md#:~:text=%22mounts%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B-,%22destination%22,-%3A%20%22/proc
    mount::<str, str, str, str>(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        None,
    )?;

    if let Err(e) = setup_cgroup() {
        eprintln!("cgroup setting error: {:?}", e);
        return Err(Errno::UnknownErrno);
    }

    Ok(())
}

fn setup_cgroup() -> Result<(), io::Error> {
    // cgorup namespaceを利用しているので、ホストとは隔離される
    let cgroup_path = &PathBuf::from("/sys/fs/cgroup");
    create_dir_all(cgroup_path)?;

    // cgroupfsのマウント
    // マウントの参考: https://gihyo.jp/admin/serial/01/linux_containers/0038#sec1
    // runcが読むconfig.jsonのprocfsの箇所: https://github.com/opencontainers/runtime-spec/blob/main/config.md#:~:text=%22nodev%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B-,%22destination%22,-%3A%20%22/sys/fs
    mount::<str, str, str, str>(
        Some("cgroup2"),
        "/sys/fs/cgroup",
        Some("cgroup2"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV | MsFlags::MS_RELATIME,
        None,
    )?;

    // プロセスIDの書き込み、cgroupを適用する
    write(
        cgroup_path.join("cgroup.procs"),
        getpid().as_raw().to_string(),
    )?;

    // メモリのハードリミットを50Mに設定する
    write(cgroup_path.join("memory.max"), "50M")?;
    Ok(())
}
