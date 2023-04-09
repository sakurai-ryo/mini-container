mount namespace
- https://blog.amedama.jp/entry/linux-mount-namespace
- https://kernhack.hatenablog.com/entry/2015/05/30/115705
- https://tech.retrieva.jp/entry/2019/04/16/155828

container impl
- https://github.com/containers/youki/
- https://github.com/opencontainers/runc/
- https://kurobato.hateblo.jp/entry/2021/05/02/164218

cgroup v2
- https://gihyo.jp/admin/serial/01/linux_containers/0037
- https://gihyo.jp/admin/serial/01/linux_containers/0038
- https://gihyo.jp/admin/serial/01/linux_containers/0039
- https://gihyo.jp/admin/serial/01/linux_containers/0049

debug
```sh
$ cargo build && strace -f -o stace.log ./target/debug/rust-container /bin/bash
```

setup
```sh
$ mkdir root
$ docker export $(docker create ubuntu) | tar -C root -xvf -
$ cargo run -- /bin/bash
```
