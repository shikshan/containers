# How containers work

Exploring the linux underpinnings of docker and containers.

## References

All credit goes to the authors of the following wonderful blog posts.

* <https://ericchiang.github.io/post/containers-from-scratch/>
* <https://jvns.ca/blog/2019/11/18/how-containers-work--overlayfs/>
* <https://medium.com/@saschagrunert/demystifying-containers-part-i-kernel-space-2c53d6979504>

## Setup

The project contains a `Vagrantfile` that runs a Fedora 31 VM.

Make sure the Vagrant Guest Additions plugin is installed: `vagrant plugin install vagrant-vbguest`.

Start the VM: `vagrant up`.

Sometimes, the guest additions update fails during the first run of `vagrant up`. In such case, install these manually using command: `vagrant vbguest --do install` and restart the VM (`vagrant halt` followed by `vagrant up`).

The project root directory on the host is mapped to `/vagrant` in the guest. All the action below takes place in the `/vagrant` directory in the guest. Change into `/vagrant` directory in the VM before carrying out steps below:

```bash
$ vagrant ssh
Last login: Sun Nov 24 19:06:40 2019 from 10.0.2.2
[vagrant@localhost ~]$ cd /vagrant
[vagrant@localhost vagrant]$
```

### Container file systems

Container images are just tarballs (or a tarball of tarballs where each layer in an image is a tarball).

#### Creating a container file system

The easiest way to get a container file system is to export it from any existing docker container on the host. The `rootfs.tar.gz` file in the project root directory has been created by exporting from a container based on `python:3.8-alpine` image: `sudo docker export <CONTAINER ID> > rootfs.tar`, changing permissions, extracting and the gzipping again.

Extract the `rootfs.tar.gz` file before embarking on the journey: `tar -xzvf rootfs.tar.gz`.

## Linux tools for containerization

### chroot

*chroot* allows us to restricts a process' view of the file system. It is a thin wrapper around syscall with the same name.

Let's restrict a process to `rootfs` directory and run commands in it.

```bash
[vagrant@localhost vagrant]$ pwd
/vagrant
[vagrant@localhost vagrant]$ ls
rootfs  README.md  Vagrantfile
[vagrant@localhost vagrant]$ python --version
Python 3.7.4
[vagrant@localhost vagrant]$ sudo chroot rootfs /bin/sh
/ # pwd
/
/ # ls
bin    dev    etc    home   lib    media  mnt    opt    proc   root   run    sbin   srv    sys    tmp    usr    var
/ # python --version
Python 3.8.0
/ #
```

**Is it contained?**

In other shell, run the `top` command.

In the *chrooted* process shell, run the following commands:

```bash
/ # mount -t proc proc /proc
/ # ps aux | grep top
 1895 1000      0:00 top
 1898 root      0:00 grep top
/ # pkill top
/ #
```

Oops! The *chrooted* shell which is running as root has no problem killing the `top` process running in host.

### namespaces

Namespaces allow us to create restricted views of systems like the process tree, network interfaces, and mounts.

A namespace can be created using *unshare* command which is a thin wrapper around syscall with the same name.

Let's create a PID namespace and execute chroot like above:

Check if proc file system is mounted on `/vagrant/rootfs/proc` using *mount* command, check the list and mount if it's not in there.

```bash
[vagrant@localhost vagrant]$ sudo mount -t proc proc $PWD/rootfs/proc
```

```bash
[vagrant@localhost vagrant]$ sudo unshare --pid --fork --mount-proc=$PWD/rootfs/proc chroot rootfs /bin/sh
/ # ls
bin    dev    etc    home   lib    media  mnt    opt    proc   root   run    sbin   srv    sys    tmp    usr    var
/ # ps aux
PID   USER     TIME  COMMAND
    1 root      0:00 sh
    3 root      0:00 ps aux
/ #
```

The *chrooted* shell is now running in a new process workspace. It thinks its PID is 1 and the host process tree is not visible anymore.

### nsenter

The nsenter command provides a wrapper around *setns* syscall to enter a namespace.

Namespaces can be composed. Processes may choose to separate some namespaces but share others. For example - some programs like Kubernetes pods have isolated PID namespaces but may choose to share a network namespace.

Lets make our namespace share the network with the host.

```bash
/ # mount -t sysfs sys /sys
/ # ls /sys/class/net
eth0  lo
/ #
```

The *chrooted* shell will have **two** PIDs: the PID inside the namespace, and the PID outside the namespace on the host system.

To use *nsenter*, we'll have to find the host PID of the *chrooted* shell. **Run the following command on the host, not the chrooted shell**.

```bash
[vagrant@localhost ~]$ ps aux | grep /bin/sh | grep root
...
root        1896  0.0  0.1   1628   712 pts/0    S+   02:30   0:00 /bin/sh
```

The kernel exposes namespaces under `/proc/(PID)/ns` as files. In this case, `/proc/1896/ns/pid` is the process namespace we’re hoping to join.

```bash
[vagrant@localhost ~]$ sudo ls -l /proc/1896/ns
total 0
lrwxrwxrwx. 1 root root 0 Nov 25 02:42 cgroup -> 'cgroup:[4026531835]'
lrwxrwxrwx. 1 root root 0 Nov 25 02:42 ipc -> 'ipc:[4026531839]'
lrwxrwxrwx. 1 root root 0 Nov 25 02:42 mnt -> 'mnt:[4026532167]'
lrwxrwxrwx. 1 root root 0 Nov 25 02:42 net -> 'net:[4026531992]'
lrwxrwxrwx. 1 root root 0 Nov 25 02:42 pid -> 'pid:[4026532168]'
lrwxrwxrwx. 1 root root 0 Nov 25 02:42 pid_for_children -> 'pid:[4026532168]'
lrwxrwxrwx. 1 root root 0 Nov 25 02:42 user -> 'user:[4026531837]'
lrwxrwxrwx. 1 root root 0 Nov 25 02:42 uts -> 'uts:[4026531838]'
[vagrant@localhost ~]$
```

Just to compare the shared and isolated namespaces of two processes, let's find out the namespaces of the host shell. Run the following commands in host shell.

```bash
[vagrant@localhost vagrant]$ echo $$
1650
[vagrant@localhost vagrant]$ sudo ls -l /proc/1650/ns
total 0
lrwxrwxrwx. 1 vagrant vagrant 0 Nov 25 03:27 cgroup -> 'cgroup:[4026531835]'
lrwxrwxrwx. 1 vagrant vagrant 0 Nov 25 03:27 ipc -> 'ipc:[4026531839]'
lrwxrwxrwx. 1 vagrant vagrant 0 Nov 25 03:27 mnt -> 'mnt:[4026531840]'
lrwxrwxrwx. 1 vagrant vagrant 0 Nov 25 03:27 net -> 'net:[4026531992]'
lrwxrwxrwx. 1 vagrant vagrant 0 Nov 25 03:27 pid -> 'pid:[4026531836]'
lrwxrwxrwx. 1 vagrant vagrant 0 Nov 25 03:27 pid_for_children -> 'pid:[4026531836]'
lrwxrwxrwx. 1 vagrant vagrant 0 Nov 25 03:27 user -> 'user:[4026531837]'
lrwxrwxrwx. 1 vagrant vagrant 0 Nov 25 03:27 uts -> 'uts:[4026531838]'
[vagrant@localhost vagrant]$
```

As you can see, all namespaces are shared except the PID one.

Now, let's join the workspace.

```bash
[vagrant@localhost vagrant]$ sudo nsenter --pid=/proc/1896/ns/pid \
>     unshare -f --mount-proc=$PWD/rootfs/proc \
>     chroot rootfs /bin/sh
/ # ps aux
PID   USER     TIME  COMMAND
    1 root      0:00 /bin/sh
    4 root      0:00 unshare -f --mount-proc=/vagrant/rootfs/proc chroot rootfs /bin/sh
    5 root      0:00 /bin/sh
    6 root      0:00 ps aux
/ #
```

Et voilà! We are in. The **PID 1** belongs to the earlier shell, while **PID 5** is for this shell.

### Mounts

Mounts can be used to inject files and directories into chroot of "immutable" containers.

Let's mount `readonlyfiles` directory of the host to a directory in chroot in read-only manner.
Run the following commands in host shell.

```bash
[vagrant@localhost vagrant]$ sudo mkdir -p rootfs/var/readonlyfiles
[vagrant@localhost vagrant]$ sudo mount --bind -o ro $PWD/readonlyfiles $PWD/rootfs/var/readonlyfiles
```

The *chrooted* shell can now see the file but can't write to it.

```bash
[vagrant@localhost vagrant]$ sudo chroot rootfs /bin/sh
/ # cat /var/readonlyfiles/hello.txt
Bonjour !
/ # # However we can't write to it
/ # echo "hello"> /var/readonlyfiles/hello.txt
/bin/sh: can't create /var/readonlyfiles/hello.txt: Read-only file system
/ #
```

Use *umount* to remove the bind mount (*rm* doesn't work).

```bash
[vagrant@localhost vagrant]$ sudo umount $PWD/rootfs/var/readonlyfiles
```

### cgroups

*cgroups* (control groups) allow kernel impose limits on resources like memory and CPU.

The kernel exposes cgroups through `/sys/fs/cgroup` directory.

```bash
[vagrant@localhost vagrant]$ ls /sys/fs/cgroup
cgroup.controllers      cgroup.procs            cgroup.threads         cpuset.mems.effective  memory.pressure
cgroup.max.depth        cgroup.stat             cpu.pressure           init.scope             system.slice
cgroup.max.descendants  cgroup.subtree_control  cpuset.cpus.effective  io.pressure            user.slice
[vagrant@localhost vagrant]$
```

#### Creating a cgroup and assigning a process to it

> Fedora 31 users CGroupsV2 by default and hence the creation steps are different than many of the resources found on internet which use V1. Here are a couple of useful links that show how to use V2:
> <https://andrestc.com/post/cgroups-io/>
> <https://pstree.cc/what-the-heck-are-linux-cgroups/>

Let's create a cgroup and assign a process to it with a memory restriction of 100mb.

1. Mount the *cgroup2* file system in `/vagrant/cgroup`.

    ```bash
    [root@localhost vagrant]# mount -t cgroup2 nodev cgroup
    [root@localhost vagrant]# cd cgroup
    [root@localhost cgroup]# ls
    cgroup.controllers      cgroup.procs            cgroup.threads         cpuset.mems.effective  memory.pressure
    cgroup.max.depth        cgroup.stat             cpu.pressure           init.scope             system.slice
    cgroup.max.descendants  cgroup.subtree_control  cpuset.cpus.effective  io.pressure            user.slice
    ```

2. Create a sub-directory `demo` under `/vagrant/cgroup`. The kernel fills the newly created directory with configuration file

   ```bash
    [root@localhost cgroup]# mkdir demo
    [root@localhost cgroup]# cd demo
    [root@localhost demo]# ls
    cgroup.controllers      cgroup.stat             io.pressure          memory.max           memory.swap.events
    cgroup.events           cgroup.subtree_control  memory.current       memory.min           memory.swap.max
    cgroup.freeze           cgroup.threads          memory.events        memory.oom.group     pids.current
    cgroup.max.depth        cgroup.type             memory.events.local  memory.pressure      pids.events
    cgroup.max.descendants  cpu.pressure            memory.high          memory.stat          pids.max
    cgroup.procs            cpu.stat                memory.low           memory.swap.current
   ```

3. Add `100mb` max memory limit to the `demo` cgroup.

    ```bash
    [root@localhost demo]# echo "100M" > memory.max
    [root@localhost demo]# echo "0" > memory.swap.max
    [root@localhost demo]# cat memory.max
    104857600
    [root@localhost demo]# cat memory.swap.max
    0
    [root@localhost demo]#
    ```

4. Add the current shell PID to `demo` cgroup.

    ```bash
    [root@localhost demo]# echo $$ > cgroup.procs
    [root@localhost demo]# cat cgroup.procs
    2164
    2254
    [root@localhost demo]#
    ```

5. We can verify the limit by running the `/vagrant/code/hogger.py` script. This script reads bytes from `/dev/urandom` in chunks of 10mb appends the bytes to an internal buffer. It will eventually exhaust the available memory if left unchecked but kernel kills it when it exceeds the memory limit of the cgroup.

    ```bash
    [root@localhost code]# python hogger.py
    10mb
    20mb
    30mb
    40mb
    50mb
    Killed
    ```

6. cgroups can’t be removed until every processes in the tasks file has exited or been reassigned to another group. Exit the shell and remove the directory with rmdir (don’t use rm -r).

    ```bash
    [vagrant@localhost vagrant]$ cd cgroup
    [vagrant@localhost cgroup]$ ls
    cgroup.controllers      cgroup.stat             cpuset.cpus.effective  io.pressure
    cgroup.max.depth        cgroup.subtree_control  cpuset.mems.effective  memory.pressure
    cgroup.max.descendants  cgroup.threads          demo                   system.slice
    cgroup.procs            cpu.pressure            init.scope             user.slice
    [vagrant@localhost cgroup]$ cat demo/cgroup.procs
    [vagrant@localhost cgroup]$ sudo rmdir demo
    [vagrant@localhost cgroup]$ ls
    cgroup.controllers      cgroup.procs            cgroup.threads         cpuset.mems.effective  memory.pressure
    cgroup.max.depth        cgroup.stat             cpu.pressure           init.scope             system.slice
    cgroup.max.descendants  cgroup.subtree_control  cpuset.cpus.effective  io.pressure            user.slice
    [vagrant@localhost cgroup]$
    ```

### Capabilities

Capabilities are a set of permissions that together make up everything a root can do.

Containers are effective means of running arbitrary code as root and therefore are a security risk. As a result, many technologies such as SELinux, seccomp, and capabilities are used to limit the power of processes already running as root and improve the security of the containers.

Let's take an example. The `/vagrant/code/server.py` is a simple http server that runs on port 80. If we try to run it directly, following is what we get:

```bash
[vagrant@localhost code]$ python server.py
Traceback (most recent call last):
  File "server.py", line 7, in <module>
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
  File "/usr/lib64/python3.7/socketserver.py", line 452, in __init__
    self.server_bind()
  File "/usr/lib64/python3.7/socketserver.py", line 466, in server_bind
    self.socket.bind(self.server_address)
PermissionError: [Errno 13] Permission denied
```

For using lower ports (< 1024), the python process in this case (or any non-root process that needs to do this) needs `CAP_NET_BIND_SERVICE` capability.

```bash
[vagrant@localhost code]$ sudo setcap cap_net_bind_service=+ep /usr/bin/python3.7
[vagrant@localhost code]$ getcap /usr/bin/python3.7
/usr/bin/python3.7 = cap_net_bind_service+ep
[vagrant@localhost code]$ python server.py
serving at port 80
```

Taking away the capability again disables the process.

```bash
[vagrant@localhost code]$ sudo setcap -r /usr/bin/python3.7
[vagrant@localhost code]$ getcap /usr/bin/python3.7
[vagrant@localhost code]$ python server.py
Traceback (most recent call last):
  File "server.py", line 7, in <module>
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
  File "/usr/lib64/python3.7/socketserver.py", line 452, in __init__
    self.server_bind()
  File "/usr/lib64/python3.7/socketserver.py", line 466, in server_bind
    self.socket.bind(self.server_address)
PermissionError: [Errno 13] Permission denied
[vagrant@localhost code]$
```

For processes already running as root, like most containerized apps, capabilities are mainly taken away.

```bash
[vagrant@localhost code]$ sudo su
[root@localhost code]# capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Ambient set =
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
 secure-no-ambient-raise: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```

As an example, let's drop a few capabilities including `CAP_CHOWN`. As a result, the shell won't be able to modify file ownership despite being root.

```bash
[vagrant@localhost vagrant]$ sudo capsh --drop=cap_chown,cap_setpcap,cap_setfcap,cap_sys_admin --
[root@localhost vagrant]# whoami
root
[root@localhost vagrant]# chown nobody /bin/ls
chown: changing ownership of '/bin/ls': Operation not permitted
```

### Overlay filesystems

*Overlay filesystems* a.k.a *union filesystems* allows us to mount a filesystem using two directories: a "lower" directory and a "upper" directory.

  * the **lower** directory is readonly
  * the **upper** directory is both read from and written to

When a process reads a file, the *overlayfs* filesystem driver looks in the upper directory and reads the file from there if it’s present. Otherwise, it looks in the lower directory.

When a process writes a file, *overlayfs* will just write it to the upper directory.

Let's create upper and lower directories and a merged directory to mount the combined filesystem into:

> Make sure to create the overlay related directories inside the VM (say, ~ i.e. home directory) instead of the host shared directory `/vagrant`.
> The latter gives the following error during mounting: `wrong fs type, bad option, bad superblock on overlay, missing codepage or helper program, or other error` if host and VM happen to be different OS's, like in my case host is *macOS* while VM is *Fedora 31*.

```bash
[vagrant@localhost /]$ cd ~
[vagrant@localhost ~]$ pwd
/home/vagrant
[vagrant@localhost ~]$ ls
[vagrant@localhost ~]$ mkdir overlayfs
[vagrant@localhost ~]$ cd overlayfs/
[vagrant@localhost overlayfs]$ pwd
/home/vagrant/overlayfs
[vagrant@localhost overlayfs]$ mkdir upper lower merged work
[vagrant@localhost overlayfs]$ echo "I'm from lower!" > lower/in_lower.txt
[vagrant@localhost overlayfs]$ echo "I'm from upper!" > upper/in_upper.txt
[vagrant@localhost overlayfs]$ # `in_both` is in both directories
[vagrant@localhost overlayfs]$ echo "I'm from lower!" > lower/in_both.txt
[vagrant@localhost overlayfs]$ echo "I'm from upper!" > upper/in_both.txt
```

Now create a overlay mount:

```bash
sudo mount -t overlay overlay -o lowerdir=./lower,upperdir=./upper,workdir=./work ./merged
```

Here are the contents of our directories after overlay:

```bash
[vagrant@localhost overlayfs]$ find lower/ upper/ merged/
lower/
lower/in_lower.txt
lower/in_both.txt
upper/
upper/in_upper.txt
upper/in_both.txt
merged/
merged/in_lower.txt
merged/in_both.txt
merged/in_upper.txt
```

#### Reading a file

Now let’s try to read one of the files from the overlay filesystem. The file `in_both.txt` exists in both `lower/` and `upper/`, so it should read the file from the `upper/` directory.

```bash
[vagrant@localhost overlayfs]$ cat merged/in_both.txt
I'm from upper!
```

#### Creating a new file

```bash
[vagrant@localhost overlayfs]$ echo 'new file' > merged/new_file
[vagrant@localhost overlayfs]$ ls -l */new_file
-rw-rw-r--. 1 vagrant vagrant 9 Nov 26 00:26 merged/new_file
-rw-rw-r--. 1 vagrant vagrant 9 Nov 26 00:26 upper/new_file
```

The new file is created in `upper` directory.

#### Deleting a file

Let's try deleting `merged/in_both.txt` and see what happens.

```bash
[vagrant@localhost overlayfs]$ rm merged/in_both.txt
[vagrant@localhost overlayfs]$ find upper/  lower/  merged/
upper/
upper/in_upper.txt
upper/in_both.txt
upper/new_file
lower/
lower/in_lower.txt
lower/in_both.txt
merged/
merged/in_lower.txt
merged/in_upper.txt
merged/new_file
[vagrant@localhost overlayfs]$ ls -l upper/in_both.txt
c---------. 1 root root 0, 0 Nov 26 00:29 upper/in_both.txt
[vagrant@localhost overlayfs]$ cat lower/in_both.txt
I'm from lower!
```

* `in_both.txt` is still in the `lower` directory, and it’s unchanged.
* it’s not in the merged directory and that is expected.
* `upper` directory shouldn't have `in_both.txt` but it still does but the `upper/in_both.txt` file is a character device now instead of the normal text file. This is called a **whiteout** in *overlayfs* terms. Quoting the [Linux overlayfs documentation](https://github.com/torvalds/linux/blob/master/Documentation/filesystems/overlayfs.txt):

  > A whiteout is created as a character device with 0/0 device number. When a whiteout is found in the upper level of a merged directory, any matching name in the lower level is ignored, and the whiteout itself is also hidden.
  >
  >A directory is made opaque by setting the xattr "trusted.overlay.opaque" to "y". Where the upper filesystem contains an opaque directory, any directory in the lower filesystem with the same name is ignored.

This is in general how docker manages storage.

### Docker images and layers

From [Docker documentation](https://docs.docker.com/storage/storagedriver/)

A Docker image is built up from a series of layers. Each layer represents an instruction in the image’s Dockerfile. Each layer except the very last one is read-only. Consider the following Dockerfile:

```Dockerfile
FROM ubuntu:18.04
COPY . /app
RUN make /app
CMD python /app/app.py
````

This Dockerfile contains four commands, each of which creates a layer. The FROM statement starts out by creating a layer from the ubuntu:18.04 image. The COPY command adds some files from your Docker client’s current directory. The RUN command builds your application using the make command. Finally, the last layer specifies what command to run within the container.

Each layer is only a set of differences from the layer before it. The layers are stacked on top of each other. When you create a new container, you add a new writable layer on top of the underlying layers. This layer is often called the “container layer”. All changes made to the running container, such as writing new files, modifying existing files, and deleting files, are written to this thin writable container layer.

The major difference between a container and an image is the top writable layer. All writes to the container that add new or modify existing data are stored in this writable layer. When the container is deleted, the writable layer is also deleted. The underlying image remains unchanged.

Because each container has its own writable container layer, and all changes are stored in this container layer, multiple containers can share access to the same underlying image and yet have their own data state.

Docker uses storage drivers to manage the contents of the image layers and the writable container layer. Each storage driver handles the implementation differently, but all drivers use stackable image layers and the copy-on-write (CoW) strategy. **OverlayFS** is one such storage driver available.

**The copy-on-write (CoW) strategy** is a strategy of sharing and copying files for maximum efficiency. If a file or directory exists in a lower layer within the image, and another layer (including the writable layer) needs read access to it, it just uses the existing file. The first time another layer needs to modify the file (when building the image or running the container), the file is copied into that layer and modified. This minimizes I/O and the size of each of the subsequent layers.
