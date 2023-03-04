---
title: "容器的三大技术--Namespace,Cgroup,UnionFS"
date: 2022-10-29T20:54:04+08:00
draft: false
categories: 
  - cloud
tags: 
  - container
  - Namespace
  - Cgroup
  - UnionFS
authors:
    - haiyux
featuredImagePreview: /img/docker.webp
---

## Namespace

### 什么是 Namespace ？

这里的 namespace 指的是 linux namespance 技术，它是一种 linux kernel 实现的一种隔离方案。即：linux os 可以为不同的进程分配不通的 namespace ，namespace之间的资源分配独立，进程彼此隔离。
如果你的 linux 安装了 gcc，那么使用 `man namespaces` 可以看到文档。也可查看[在线手册](http://man7.org/linux/man-pages/man7/namespaces.7.html)。

### 介绍

下图为各种 namespace 的参数，支持的起始内核版本，以及隔离内容。

| Namespace                         | 系统调用参数  | 内核版本     | 隔离内容                   |
| --------------------------------- | ------------- | ------------ | -------------------------- |
| UTS (Unix Time-sharing System)    | CLONE_NEWUTS  | Linux 2.4.19 | 主机名与域名               |
| IPC (Inter-Process Communication) | CLONE_NEWIPC  | Linux 2.6.19 | 信号量、消息队列和共享内存 |
| PID (Process ID)                  | CLONE_NEWPID  | Linux 2.6.19 | 进程编号                   |
| Network                           | CLONE_NEWNET  | Linux 2.6.24 | 网络设备、网络栈、端口等等 |
| Mount                             | CLONE_NEWNS   | Linux 2.6.29 | 挂载点（文件系统）         |
| User                              | CLONE_NEWUSER | Linux 3.8    | 用户和用户组               |

1. pid namespace
    - 不同用户的进程就是通过pid namespace隔离开的，且不同 namespace  中可以有相同pid。所有的LXC进程在docker中的父进程为docker进程，每个lxc进程具有不同的namespace。同时由于允许嵌套，因此可以很方便的实现 Docker in Docker。

2. net namespace
    - 有了 pid namespace,  每个namespace中的pid能够相互隔离，但是网络端口还是共享host的端口。网络隔离是通过net namespace实现的， 每个net  namespace有独立的 network devices, IP addresses, IP routing tables,  /proc/net  目录。这样每个container的网络就能隔离开来。docker默认采用veth的方式将container中的虚拟网卡同host上的一个docker bridge: docker0连接在一起。

3. ipc namespace
    - container中进程交互还是采用linux常见的进程间交互方法(interprocess communication - IPC), 包括常见的信号量、消息队列和共享内存。然而同 VM 不同的是，container 的进程间交互实际上还是host上具有相同pid  namespace中的进程间交互，因此需要在IPC资源申请时加入namespace信息 - 每个IPC资源有一个唯一的 32 位 ID。

4. mnt namespace
    - 类似chroot，将一个进程放到一个特定的目录执行。mnt  namespace允许不同namespace的进程看到的文件结构不同，这样每个 namespace  中的进程所看到的文件目录就被隔离开了。同chroot不同，每个namespace中的container在/proc/mounts的信息只包含所在namespace的mount point。

5. uts namespace
    - UTS("UNIX Time-sharing System") namespace允许每个container拥有独立的hostname和domain name, 使其在网络上可以被视作一个独立的节点而非Host上的一个进程。

6. user namespace
    - 每个container可以有不同的 user 和 group id, 也就是说可以在container内部用container内部的用户执行程序而非Host上的用户。

还设计到三个系统调用(system call)的 API：

- clone()：用来创建新进程，与 fork 创建新进程不同的是，clone 创建进程时候运行传递如 CLONE_NEW* 的 namespace 隔离参数，来控制子进程所共享的内容，更多内容请查看[clone 手册](http://man7.org/linux/man-pages/man2/clone.2.html)
- setns()：让某个进程脱离某个 namespace
- unshare()：让某个进程加入某个 namespace 之中

### namespace的操作

• 查看当前系统的 namespace

```bash
lsns –t <type>
```

• 查看某进程的 namespace

```bash
ls -la /proc/<pid>/ns/
```

• 进入某 namespace 运行命令

```bash
nsenter -t <pid> -n ip addr
```

**实验一下：**

1. docker启动一个 centos

```bash
docker run --rm -it centos bash
```

2. 用另一个窗口 找到这个进程

```bash
ps -ef|grep centos
root        2931    2909  0 14:52 pts/1    00:00:00 docker run --rm -it centos bash
root        3401    1594  0 14:53 pts/0    00:00:00 grep --color=auto centos
```

3. 查看这个进程的 namespace

```bash
ls -la /proc/2931/ns/
total 0
dr-x--x--x 2 root root 0 Oct 29 14:55 .
dr-xr-xr-x 9 root root 0 Oct 29 14:53 ..
lrwxrwxrwx 1 root root 0 Oct 29 14:55 cgroup -> 'cgroup:[4026531835]'
lrwxrwxrwx 1 root root 0 Oct 29 14:55 ipc -> 'ipc:[4026531839]'
lrwxrwxrwx 1 root root 0 Oct 29 14:55 mnt -> 'mnt:[4026531841]'
lrwxrwxrwx 1 root root 0 Oct 29 14:55 net -> 'net:[4026531840]'
lrwxrwxrwx 1 root root 0 Oct 29 14:55 pid -> 'pid:[4026531836]'
lrwxrwxrwx 1 root root 0 Oct 29 14:55 pid_for_children -> 'pid:[4026531836]'
lrwxrwxrwx 1 root root 0 Oct 29 14:55 time -> 'time:[4026531834]'
lrwxrwxrwx 1 root root 0 Oct 29 14:55 time_for_children -> 'time:[4026531834]'
lrwxrwxrwx 1 root root 0 Oct 29 14:55 user -> 'user:[4026531837]'
lrwxrwxrwx 1 root root 0 Oct 29 14:55 uts -> 'uts:[4026531838]'
```

4. 在centos中执行 `ip addr`  在主机执行 `nsenter -t <pid> -n ip addr`

```bash
# centos 执行 ip addr
ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
10: eth0@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
       
# 主机上执行 nsenter -t 2931 -n ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
```

发现结果是相同的

## Cgroup

### 什么是Cgroup

Linux cgroups 的全称是 Linux Control Groups，它是 Linux 内核的特性，主要作用是**限制、记录和隔离进程组（process groups）使用的物理资源（cpu、memory、IO 等）**。

### 作用

cgroups 从设计之初使命就很明确，为进程提供资源控制，它主要的功能包括：

- **资源限制**：限制进程使用的资源上限，比如最大内存、文件系统缓存使用限制
- **优先级控制**：不同的组可以有不同的优先级，比如 CPU 使用和磁盘 IO 吞吐
- **审计**：计算 group 的资源使用情况，可以用来计费
- **控制**：挂起一组进程，或者重启一组进程

目前 cgroups 已经成为很多技术的基础，比如 LXC、docker、systemd等。

### 核心概念

- **task**：任务，对应于系统中运行的一个实体，一般是指进程
- **subsystem**：子系统，具体的资源控制器（resource class 或者 resource controller），控制某个特定的资源使用。比如 CPU 子系统可以控制 CPU 时间，memory 子系统可以控制内存使用量
- **cgroup**：控制组，一组任务和子系统的关联关系，表示对这些任务进行怎样的资源管理策略
- **hierarchy**：层级树，一系列 cgroup 组成的树形结构。每个节点都是一个 cgroup，cgroup 可以有多个子节点，子节点默认会继承父节点的属性。系统中可以有多个 hierarchy

### subsystem

subsystem 是一组资源控制的模块，一般包含有：

- blkio 设置对块设备(比如硬盘)的输入输出的访问控制(block/io)
- cpu 设置cgroup中的进程的CPU被调度的策略
- cpuacct 可以统计cgroup中的进程的CPU占用(cpu account)
- cpuset 在多核机器上设置cgroup中的进程可以使用的CPU和内存(此处内存仅使用于NUMA架构)
- devices 控制cgroup中进程对设备的访问
- freezer 用于挂起(suspends)和恢复(resumes) cgroup中的进程
- memory 用于控制cgroup中进程的内存占用
- net_cls 用于将cgroup中进程产生的网络包分类(classify)，以便Linux的tc(traffic controller) (net_classify) 可以根据分类(classid)区分出来自某个cgroup的包并做限流或监控。
- net_prio 设置cgroup中进程产生的网络流量的优先级
- ns 这个subsystem比较特殊，它的作用是cgroup中进程在新的namespace fork新进程(NEWNS)时，创建出一个新的cgroup，这个cgroup包含新的namespace中进程。

### CPU 子系统

- cpu.shares：	  时间相对值，比如一共3个核，进程A是1024，进程B是2048那么A能用一个核，B能用两个
- cpu.cfs_period_us：时间周期长度，单位为 us。
- cpu.cfs_quota_us： 在 cfs_period_us 内能使用的 CPU 时间，单位为 us。
- cpu.stat ：使用的 CPU 时间统计。	
- nr_periods ： 经过多好个 cpu.cfs_period_us 的周期。
- nr_throttled ： 在经过的周期内，有多少次因为进程在指定的时间周期内用光了 cpu.cfs_quota_us 而受到限制。 
- throttled_time ：进程被限制使用 CPU 的总用时，单位是 ns。

### cpuacct 子系统

用于统计 Cgroup 及其子 Cgroup 下进程的 CPU 的使用情况。

- cpuacct.usage 包含该 Cgroup 及其子 Cgroup 下进程使用 CPU 的时间，单位是 ns（纳秒）。
- cpuacct.stat 包含该 Cgroup 及其子 Cgroup 下进程使用的 CPU 时间，以及用户态和内核态的时间。

### Memory 子系统

- memory.usage_in_bytes
    cgroup 下进程使用的内存，包含 cgroup 及其子 cgroup 下的进程使用的内存
- memory.max_usage_in_bytes
    cgroup 下进程使用内存的最大值，包含子 cgroup 的内存使用量。
- memory.limit_in_bytes
    设置 Cgroup 下进程最多能使用的内存。如果设置为 -1，表示对该 cgroup 的内存使用不做限制。
- memory.soft_limit_in_bytes
    这个限制并不会阻止进程使用超过限额的内存，只是在系统内存足够时，会优先回收超过限额的内存，使之向限定值靠拢。
- memory.oom_control
    设置是否在 Cgroup 中使用 OOM（Out of Memory）Killer，默认为使用。当属于该 cgroup 的进程使用的内存超过最大的限定值时，会立刻被 OOM Killer 处理。

## UnionFS

联合文件系统（[UnionFS](http://en.wikipedia.org/wiki/UnionFS)）是一种分层、轻量级并且高性能的文件系统，它支持对文件系统的修改作为一次提交来一层层的叠加，同时可以将不同目录挂载到同一个虚拟文件系统下(unite several directories into a single virtual filesystem)。

联合文件系统是 Docker 镜像的基础。镜像可以通过分层来进行继承，基于基础镜像（没有父镜像），可以制作各种具体的应用镜像。

另外，不同 Docker 容器就可以共享一些基础的文件系统层，同时再加上自己独有的改动层，大大提高了存储的效率。

Docker 中使用的 AUFS（AnotherUnionFS）就是一种联合文件系统。 AUFS 支持为每一个成员目录（类似 Git  的分支）设定只读（readonly）、读写（readwrite）和写出（whiteout-able）权限, 同时 AUFS  里有一个类似分层的概念, 对只读权限的分支可以逻辑上进行增量地修改(不影响只读部分的)。

Docker 目前支持的联合文件系统种类包括 AUFS, btrfs, vfs 和 DeviceMapper

### docker iamge

![image-20211201222838353](/images/image-20211201222838353.png)

每一条指令是一层

### Docker 的文件系统

典型的 Linux 文件系统组成：

- Bootfs（boot file system）
    - Bootloader - 引导加载 kernel，
    - Kernel - 当 kernel 被加载到内存中后 umount bootfs。
- rootfs （root file system）
    - /dev，/proc，/bin，/etc 等标准目录和文件。
    - 对于不同的 linux 发行版, bootfs 基本是一致的，但 rootfs 会有差别。

### Docker 启动

Linux

- 在启动后，首先将 rootfs 设置为 readonly, 进行一系列检查, 然后将其切换为 “readwrite”供用户使用。

Docker 启动

- 初始化时也是将 rootfs 以 readonly 方式加载并检查，然而接下来利用 union mount 的方式将一个readwrite 文件系统挂载在 readonly 的 rootfs 之上；
- 并且允许再次将下层的 FS（file system） 设定为 readonly 并且向上叠加。 这样一组 readonly 和一个 writeable 的结构构成一个 container 的运行时态, 每一个 FS 被称作一个 FS层。

### 写操作

由于镜像具有共享特性，所以对容器可写层的操作需要依赖存储驱动提供的写时复制和用时分配机制，以此来 支持对容器可写层的修改，进而提高对存储和内存资源的利用率。

- 写时复制 即 Copy-on-Write。
    - 一个镜像可以被多个容器使用，但是不需要在内存和磁盘上做多个拷贝。
    - 在需要对镜像提供的文件进行修改时，该文件会从镜像的文件系统被复制到容器的可写层的文件系统 进行修改，而镜像里面的文件不会改变。
    - 不同容器对文件的修改都相互独立、互不影响。
- 用时分配
- 按需分配空间，而非提前分配，即当一个文件被创建出来后，才会分配空间。

### 容器存储驱动

> 现在主流基本都是 overlayFS

![image-20211201222938917](/images/image-20211201222938917.png)

![image-20211201222959450](/images/image-20211201222959450.png)

### 以 OverlayFS 为 例

OverlayFS 也是一种与 AUFS 类似的联合文件系统，同样属于文件级的存储驱动，包含了最初的 Overlay 和更新更稳定的 overlay2。

Overlay 只有两层：upper 层和 lower 层，Lower 层代表镜像层，upper 层代表容器可写层。

![image-20211201223026631](/images/image-20211201223026631.png)

## Reference

1. https://jiajially.gitbooks.io/dockerguide/content/dockerCoreNS.html
2. https://creaink.github.io/post/Computer/Linux/Linux-namespace.html
3. https://cizixs.com/2017/08/25/linux-cgroup/
4. https://www.l6bj.com/post/cloudnative/docker/03-cgroup/
5. https://docker-practice.readthedocs.io/en/stable/underly/ufs/
6. https://www.l6bj.com/post/cloudnative/docker/04-unionfs/

