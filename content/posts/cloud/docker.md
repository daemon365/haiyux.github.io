---
title: "Docker"
date: 2020-12-12T17:30:43+08:00
draft: false
toc: true
categories: [cloud]
tags: [cloud,docker]
authors:
    - haiyux
---

## docker的定义

Docker 最初是 dotCloud 公司创始人 Solomon Hykes 在法国期间发起的一个公司内部项目，于 2013 年 3 月以 Apache 2.0 授权协议开源，主要项目代码在 GitHub 上进行维护。
Docker 使用 Google 公司推出的 Go 语言 进行开发实现。
docker是linux容器的一种封装，提供简单易用的容器使用接口。它是最流行的Linux容器解决方案。
docker的接口相当简单，用户可以方便的创建、销毁容器。
docker将应用程序与程序的依赖，打包在一个文件里面。运行这个文件就会生成一个虚拟容器。
程序运行在虚拟容器里，如同在真实物理机上运行一样，有了docker，就不用担心环境问题了。

## docker和虚拟机的区别

| 特性    | 容器        | 虚拟机    |
| ----- | --------- | ------ |
| 启动    | 秒级        | 分钟级    |
| 硬盘使用  | 一般为 MB    | 一般为 GB |
| 性能    | 接近原生      | 弱      |
| 系统支持量 | 单机支持上千个容器 | 一般几十个  |

虚拟机也可以制作模板，基于模板创建虚拟机，保证环境问题一致

虚拟机（virtual machine）就是带环境安装的一种解决方案。它可以在一种操作系统里面运行另一种操作系统，比如在 Windows 系统里面运行 Linux 系统。应用程序对此毫无感知，因为虚拟机看上去跟真实系统一模一样，而对于底层系统来说，虚拟机就是一个普通文件，不需要了就删掉，对其他部分毫无影响。

虽然用户可以通过虚拟机还原软件的原始环境。但是，这个方案有几个缺点。

1. 资源占用多冗余
2. 步骤多
3. 启动慢

**用上docker容器后，可以实现开发、测试和生产环境的统一化和标准化。**

**镜像作为标准的交付件，可在开发、测试和生产环境上以容器来运行，最终实现三套环境上的应用以及运行所依赖内容的完全一致。**

**Linux容器不是模拟一个完整的操作系统，而是对进程进行隔离。在正常进程的外面套了一个保护层，对于容器里面进程来说，它接触的资源都是虚拟的，从而实现和底层系统的隔离。**

1. 启动快
2. 资源占用少
3. 体积小

![](/images/2344773-20210819234116062-1846095838.png)

### docker容器的优势

* 更高效的利用系统资源
* 更快速的启动时间
* 持续交付和部署
* 更轻松的迁移

![](/images/2344773-20210819234107267-1368724918.png)

## docker的三大概念

### 镜像 image

* Docker镜像就是一个只读的模板。
* 镜像可以用来创建Docker容器。
* Docker提供了一个很简单的机制来创建镜像或者更新现有的镜像，用户甚至可以直接从其他人那里下载一个已经做好的镜像来直接使用。

**镜像的分层存储**

* 因为镜像包含完整的root文件系统，体积是非常庞大的，因此docker在设计时按照Union FS的技术，将其设计为分层存储的架构。
* 镜像不是ISO那种完整的打包文件，镜像只是一个虚拟的概念，他不是一个完整的文件，而是由一组文件组成，或者多组文件系统联合组成。

### 容器 container

* 容器是镜像运行时的实体
* 容器可以被创建、启动、停止、删除、暂停
* 容器是从镜像创建的运行实例。它可以被启动、开始、停止、删除。每个容器都是相互隔离的，保证安全的平台。
* Docker利用容器来运行应用。

### 仓库 repository

* 仓库是集中存放镜像文件的场所。有时候把仓库和仓库注册服务器（Registry）混为一谈，并不严格区分。实际上，仓库注册服务器上往往存放着多个仓库，每个仓库中又包含了多个镜像，每个镜像有不同的标签(tag)。
* 仓库分为公开仓库(Public)和私有仓库(Private)两种形式。
* 最大的公开仓库是Docker Hub，存放了数量庞大的镜像供用户下载。国内的公开仓库包括Docker Pool等，可以提供大陆用户更稳定快读的访问。
* 当用户创建了自己的镜像之后就可以使用push命令将它上传到公有或者私有仓库，这样下载在另外一台机器上使用这个镜像时候，只需需要从仓库上pull下来就可以了。
* 注意：Docker仓库的概念跟Git类似，注册服务器可以理解为GitHub这样的托管服务。

## docker安装

1. 卸载旧版本
   
   ```shell
   sudo yum remove docker \
                     docker-client \
                     docker-client-latest \
                     docker-common \
                     docker-latest \
                     docker-latest-logrotate \
                     docker-logrotate \
                     docker-selinux \
                     docker-engine-selinux \
                     docker-engine
   ```

2. 设置存储库
   
   ```shell
   sudo yum install -y yum-utils \
     device-mapper-persistent-data \
     lvm2
   sudo yum-config-manager \
       --add-repo \
       https://download.docker.com/linux/centos/docker-ce.repo
   ```

3. 安装docker社区版
   
   ```
   sudo yum install docker-ce
   ```

4. 启动关闭docker
   
   ```shell
   systemctl start docker
   ```

5. docker镜像加速
   
   vim /etc/docker/daemon.json写以下内容
   
   ```json
   {
       "registry-mirrors": ["https://kuamavit.mirror.aliyuncs.com", "https://registry.docker-cn.com","https://docker.mirrors.ustc.edu.cn"],
       "max-concurrent-downloads": 10,
       "storage-driver": "overlay2",
       "graph": "/data/docker",
         "log-driver": "json-file",
         "log-level": "warn",
         "log-opts": {
           "max-size": "10m",
           "max-file": "3"
       }
   }
   ```

## docker基本命令

选择参数:

1. --config=~/.dockerLocation of client config files 客户端配置文件的位置
2. -D, --debug=falseEnable debug mode 启用Debug调试模式
3. -H, --host=[]Daemon socket(s) to connect to 守护进程的套接字（Socket）连接
4. -h, --help=falsePrint usage 打印使用
5. -l, --log-level=infoSet the logging level 设置日志级别
6. --tls=falseUse TLS; implied by--tlsverify 证书
7. --tlscacert=~/.docker/ca.pemTrust certs signed only by this CA 信任证书签名CA
8. --tlscert=~/.docker/cert.pemPath to TLS certificate file TLS证书文件路径
9. --tlskey=~/.docker/key.pemPath to TLS key file TLS密钥文件路径
10. --tlsverify=falseUse TLS and verify the remote 使用TLS验证远程
11. -v, --version=falsePrint version information and quit 打印版本信息并退出

指令:

1. attach Attach to a running container 当前shell下attach连接指定运行镜像
2. build Build an image from a Dockerfile 通过Dockerfile定制镜像
3. commit Create a new image from a container's changes 提交当前容器为新的镜像
4. cp Copy files/folders from a container to a HOSTDIR or to STDOUT 从容器中拷贝指定文件或者目录到宿主机中
5. create Create a new container 创建一个新的容器，同run 但不启动容器
6. diff Inspect changes on a container's filesystem 查看docker容器变化
7. events Get real time events from the server 从docker服务获取容器实时事件
8. exec Run a command in a running container 在已存在的容器上运行命令
9. export Export a container's filesystem as a tar archive 导出容器的内容流作为一个tar归档文件(对应import)
10. history Show the history of an image 展示一个镜像形成历史
11. images List images 列出系统当前镜像
12. import Import the contents from a tarball to create a filesystem image 从tar包中的内容创建一个新的文件系统映像(对应export)
13. info Display system-wide information 显示系统相关信息
14. inspect Return low-level information on a container or image 查看容器详细信息
15. kill Kill a running container kill指定docker容器
16. load Load an image from a tar archive or STDIN 从一个tar包中加载一个镜像(对应save)
17. login Register or log in to a Docker registry 注册或者登陆一个docker源服务器
18. logout Log out from a Docker registry 从当前Docker registry退出
19. logs Fetch the logs of a container 输出当前容器日志信息
20. pause Pause all processes within a container 暂停容器
21. port List port mappings or a specific mapping for the CONTAINER 查看映射端口对应的容器内部源端口
22. ps List containers 列出容器列表
23. pull Pull an image or a repository from a registry 从docker镜像源服务器拉取指定镜像或者库镜像
24. push Push an image or a repository to a registry 推送指定镜像或者库镜像至docker源服务器
25. rename Rename a container 重命名容器
26. restart Restart a running container 重启运行的容器
27. rm Remove one or more containers 移除一个或者多个容器
28. rmi Remove one or more images 移除一个或多个镜像(无容器使用该镜像才可以删除，否则需要删除相关容器才可以继续或者-f强制删除)
29. run Run a command in a new container 创建一个新的容器并运行一个命令
30. save Save an image(s) to a tar archive 保存一个镜像为一个tar包(对应load)
31. search Search the Docker Hub for images 在docker

镜像:

1. start Start one or more stopped containers 启动容器
2. stats Display a live stream of container(s) resource usage statistics 统计容器使用资源
3. stop Stop a running container 停止容器
4. tag Tag an image into a repository 给源中镜像打标签
5. top Display the running processes of a container 查看容器中运行的进程信息
6. unpause Unpause all processes within a container 取消暂停容器
7. version Show the Docker version information 查看容器版本号
8. wait Block until a container stops, then print its exit code 截取容器停止时的退出状态值

## 运行hello-world镜像

命令:docker run hello-world

```shell
[root@VM-0-3-centos ~]## docker run hello-world
Unable to find image 'hello-world:latest' locally
latest: Pulling from library/hello-world
0e03bdcc26d7: Pull complete 
Digest: sha256:7f0a9f93b4aa3022c3a4c147a449bf11e0941a1fd0bf4a8e6c9408b2600777c5
Status: Downloaded newer image for hello-world:latest
Hello from Docker!
This message shows that your installation appears to be working correctly.
To generate this message, Docker took the following steps:
 1\. The Docker client contacted the Docker daemon.
 2\. The Docker daemon pulled the "hello-world" image from the Docker Hub.
    (amd64)
 3\. The Docker daemon created a new container from that image which runs the
    executable that produces the output you are currently reading.
 4\. The Docker daemon streamed that output to the Docker client, which sent it
    to your terminal.
To try something more ambitious, you can run an Ubuntu container with:
 $ docker run -it ubuntu bash
Share images, automate workflows, and more with a free Docker ID:
 https://hub.docker.com/
For more examples and ideas, visit:
 https://docs.docker.com/get-started/
```

## 运行linux容器

1. 下载imagedocker pull centos
   
   ```shell
   [root@VM-0-3-centos ~]## docker pull centos
   Using default tag: latest
   latest: Pulling from library/centos
   Digest: sha256:76d24f3ba3317fa945743bb3746fbaf3a0b752f10b10376960de01da70685fbd
   Status: Image is up to date for centos:latest
   docker.io/library/centos:latest
   ```

2. 运行centosdocker run -it --rm centos bash
   
   * -i 是交互式操作，-t是终端
   * 容器退出后将其删除
   * centos为镜像
   * 指定用交互式的shell，因此需要bash命令
   
   ```shell
   [root@VM-0-3-centos ~]## docker run -it --rm centos bash
   [root@33be613ee1eb /]## username -a
   bash: username: command not found
   [root@33be613ee1eb /]## cat /proc/version 
   Linux version 3.10.0-1062.18.1.el7.x86_64 (mockbuild@kbuilder.bsys.centos.org) (gcc version 4.8.5 20150623 (Red Hat 4.8.5-39) (GCC) ) #1 SMP Tue Mar 17 23:49:17 UTC 2020
   [root@33be613ee1eb /]## exit
   exit
   [root@VM-0-3-centos ~]#
   ```

3. 后台模式启动docker-d后台运行容器，返回容器ID
   
   * 进入容器 使用-d参数时，容器启动后会进入后台,想进入容器操作
     
     ```shell
     docker  exec -it 容器id
     docker attach 容器id
     ```

## 提交创建自定义的镜像(docker container commit)

1. 我们进入交互式的centos容器中，发现没有vim命令docker run -it centos

2. 在当前容器中，安装一个vimyum install -y vim

3. 安装好vim之后，exit退出容器exit

4. 查看刚才安装好vim的容器记录docker container ls -a

5. 提交这个容器，创建新的imagedocker commit 059fdea031ba zhy

6. 查看镜像文件

## 外部访问容器

* 容器中可以运行网络应用，但是要让外部也可以访问这些应用，可以通过-p或-P参数指定端口映射。-P参数会随机映射端口到容器开放的网络端口
* 检查映射的端口docker ps -l
* 查看容器日志信息docker logs -f cfd不间断显示log
* 外部访问服务器的端口

**查看指定容器的端口映射** docker port 76d

**查看容器内的进程** docker top 76d

## docer数据卷

### Docker volume使用

Docker中的数据可以存储在类似于虚拟机磁盘的介质中，在Docker中称为数据卷（Data Volume）。数据卷可以用来存储Docker应用的数据，也可以用来在Docker容器间进行数据共享。
数据卷呈现给Docker容器的形式就是一个目录，支持多个容器间共享，修改也不会影响镜像。使用Docker的数据卷，类似在系统中使用 mount 挂载一个文件系统。

1. 一个数据卷是一个特别指定的目录，该目录利用容器的UFS文件系统可以为容器提供一些稳定的特性或者数据共享。数据卷可以在多个容器之间共享。
2. 创建数据卷，只要在docker run命令后面跟上-v参数即可创建一个数据卷，当然也可以跟多个-v参数来创建多个数据卷，当创建好带有数据卷的容器后，
   就可以在其他容器中通过--volumes-froms参数来挂载该数据卷了，而不管该容器是否运行。也可以在Dockerfile中通过VOLUME指令来增加一个或者多个数据卷。
3. 如果有一些数据想在多个容器间共享，或者想在一些临时性的容器中使用该数据，那么最好的方案就是你创建一个数据卷容器，然后从该临时性的容器中挂载该数据卷容器的数据。这样，即使删除了刚开始的第一个数据卷容器或者中间层的数据卷容器，只要有其他容器使用数据卷，数据卷都不会被删除的。
4. 不能使用docker export、save、cp等命令来备份数据卷的内容，因为数据卷是存在于镜像之外的。备份的方法可以是创建一个新容器，挂载数据卷容器，同时挂载一个本地目录，然后把远程数据卷容器的数据卷通过备份命令备份到映射的本地目录里面。如下：docker run -rm --volumes-from DATA -v $(pwd):/backup busybox tar cvf /backup/backup.tar /data
5. 也可以把一个本地主机的目录当做数据卷挂载在容器上，同样是在docker run后面跟-v参数，不过-v后面跟的不再是单独的目录了，它是[host-dir]:[container-dir]:[rw|ro]这样格式的，host-dir是一个绝对路径的地址，如果host-dir不存在，则docker会创建一个新的数据卷，如果host-dir存在，但是指向的是一个不存在的目录，则docker也会创建该目录，然后使用该目录做数据源。

Docker Volume数据卷可以实现：

1. 绕过“拷贝写”系统，以达到本地磁盘IO的性能，（比如运行一个容器，在容器中对数据卷修改内容，会直接改变宿主机上的数据卷中的内容，所以是本地磁盘IO的性能，而不是先在容器中写一份，最后还要将容器中的修改的内容拷贝出来进行同步。）
2. 绕过“拷贝写”系统，有些文件不需要在docker commit打包进镜像文件。
3. 数据卷可以在容器间共享和重用数据
4. 数据卷可以在宿主和容器间共享数据
5. 数据卷数据改变是直接修改的
6. 数据卷是持续性的，直到没有容器使用它们。即便是初始的数据卷容器或中间层的数据卷容器删除了，只要还有其他的容器使用数据卷，那么里面的数据都不会丢失。

Docker数据持久化：

* 容器在运行期间产生的数据是不会写在镜像里面的，重新用此镜像启动新的容器就会初始化镜像，会加一个全新的读写入层来保存数据。
* 如果想做到数据持久化，Docker提供数据卷（Data volume）或者数据容器卷来解决问题，另外还可以通过commit提交一个新的镜像来保存产生的数据。

### 创建一个数据卷

docker run -it --name=myubuntu -v /home/flynngod/bin/MainDataVolume:/ContainerDataVolume /bin/hash

* --name是给创建的容器取名
* -v后的MainDataVolume是在宿主机上创建的文件夹名，用 : 将宿主机和容器的路径隔开；ContainerDataVolume是容器上的
  创建完成后，在容器中touch文件test.txt并写入一行字符串：

在宿主机中可以看到同样的文件:

* 同样的，如果在宿主机这端创建文件或者修改文件，容器中也会有相同的变化。如果说，容器中只能有读取文件权限，而无法修改的话，可以这么写.... -v /home/flynngod/bin/MainDataVolume:/ContainerDataVolume:ro，在-v后添加:ro就行了。如果需要创建多个容器数据卷，那么久在后面再添加一个 -v + 宿主机和容器的目录路径。

### 数据卷的备份和还原

数据卷备份使用的命令：
docker run --volumes-from 存在的容器名 -v $(pwd):/backup --name 新建的容器名 镜像名 tar cvf /backup/backup.tar 数据卷

backup.tar压缩文件只是对容器中的ContainerDataVolume文件夹的压缩。同时会生成容器的备份容器，使用docker ps -a可以查看到。

数据卷还原的命令:
docker run --volumes-from 存在的容器名 -v $(pwd):/backup --name 新建的容器名 镜像名 tar xvf /backup/backup.tar

### 删除数据卷

Volume 只有在下列情况下才能被删除：

1. docker rm -v删除容器时添加了-v选项
2. docker run --rm运行容器时添加了--rm选项

否则，会在/var/lib/docker/volumes目录中遗留很多不明目录。

## dockerfile

1. FROM

```
FROM 
```

* FROM指定构建镜像的基础源镜像，如果本地没有指定的镜像，则会自动从 Docker 的公共库 pull 镜像下来。

* FROM必须是 Dockerfile 中非注释行的第一个指令，即一个 Dockerfile 从FROM语句开始。

* 如果FROM语句没有指定镜像标签，则默认使用latest标签。

* FROM可以在一个 Dockerfile 中出现多次，如果有需求在一个 Dockerfile 中创建多个镜像。
2. MAINTAINER

```
MAINTAINER 
```

* 指定创建镜像的用户
3. RUN

```
RUN "executable", "param1", "param2"
```

* 每条RUN指令将在当前镜像基础上执行指定命令，并提交为新的镜像，后续的RUN都在之前RUN提交后的镜像为基础，镜像是分层的，可以通过一个镜像的任何一个历史提交点来创建，类似源码的版本控制。
4. CMD
* CMD的目的是为了在启动容器时提供一个默认的命令执行选项。如果用户启动容器时指定了运行的命令，则会覆盖掉CMD指定的命令。
* CMD指定在 Dockerfile 中只能使用一次，如果有多个，则只有最后一个会生效。

```
CMD ["executable","param1","param2"]
CMD ["param1","param2"]
CMD command param1 param2 (shell form)
```

> RUN 和CMD的区别：
> CMD会在启动容器的时候执行，build 时不执行。
> RUN只是在构建镜像的时候执行

5. EXPOSE

```
EXPOSE  [...]
```

* 告诉 Docker 服务端容器对外映射的本地端口，需要在 docker run 的时候使用-p或者-P选项生效
6. ENV

```
ENV         ## 只能设置一个变量
ENV = ...   ## 允许一次设置多个变量
```

* 指定一个环境变量，会被后续RUN指令使用，可以在容器内被脚本或者程序调用。
7. ADD

```
ADD ... 
```

* ADD复制本地主机文件、目录到目标容器的文件系统中。

* 如果源是一个URL，该URL的内容将被下载并复制到目标容器中。
8. COPY

```
COPY ... 
```

* COPY复制新文件或者目录到目标容器指定路径中 。

* 用法和功能同ADD，区别在于不能用URL，ADD功能更强大些。
9. ENTRYPOINT

```
ENTRYPOINT ["executable", "param1", "param2"]
ENTRYPOINT command param1 param2 (shell form)
```

* 配置容器启动后执行的命令，并且不可被 docker run 提供的参数覆盖，而CMD是可以被覆盖的。如果需要覆盖，则可以使用docker run --entrypoint选项。
* 每个 Dockerfile 中只能有一个ENTRYPOINT，当指定多个时，只有最后一个生效。

> 疑问: ENTRYPOINT 和 CMD 可同时存在吗？
> 测试结果：可以的。
> 两者使用场景：
> ENTRYPOINT 用于稳定-不被修改的执行命令。
> CMD 用于 可变的命令。

10. VOLUME

```
VOLUME ["/data"]
```

* 将本地主机目录挂载到目标容器中

* 将其他容器挂载的挂载点 挂载到目标容器中
11. USER

```
USER mysql
```

* 指定运行容器时的用户名或 UID，

* 在这之后的命令如RUN、CMD、ENTRYPOINT也会使用指定用户
12. WORKDIR

```
WORKDIR /path/to/workdir
```

* 切换目录，相当于cd
13. ONBUILD

```
ONBUILD [INSTRUCTION]
```

* 使用该dockerfile生成的镜像A，并不执行ONBUILD中命令
* 如再来个dockerfile 基础镜像为镜像A时，生成的镜像B时就会执行ONBUILD中的命令

## docker-compose

docker-compose是 docker 官方的开源项目，使用 python 编写，实现上调用了 Docker 服务的 API 进行容器管理。其官方定义为为 「定义和运行多个 Docker 容器的应用（Defining and running multi-container Docker applications）），其实就是上面所讲的功能。

### 安装

1. sudo curl -L "https://github.com/docker/compose/releases/download/1.26.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
2. sudo chmod +x /usr/local/bin/docker-compose
3. sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
4. docker-compose --version查看

### 简介

类似 docker 的Dockerfile文件，docker-compose使用 YAML 文件对容器进行管理。

对于 docker-compose 有两个基本的概念：

* 服务(service)：一个应用容器，即 docker 容器，比如之前所说的mysql 容器、nginx 容器
* 项目(project)：由一组关联的应用容器组成的一个完整业务单元，比如上面所讲的由 mysql、web app、nginx 容器组成的网站。docker-compose 面向项目进行管理。

YAML 文件格式。

1.大小写敏感，缩进表示表示层级关系

2.缩进空格数不重要，相同层级左侧对齐即可。（不允许使用 tab 缩进！）

3.由冒号分隔的键值对表示对象；一组连词线开头的行，构成一个数组；字符串默认不使用引号

### docker-compose区域

**services**

* 服务，在它下面可以定义应用需要的一些服务，每个服务都有自己的名字、使用的镜像、挂载的数据卷、所属的网络、依赖哪些其他服务等等。

**volumes**

* 数据卷，在它下面可以定义的数据卷（名字等等），然后挂载到不同的服务下去使用。

**networks**

* 应用的网络，在它下面可以定义应用的名字、使用的网络类型等等。

```dockerfile
version: '2.0'
services:
  nginx:
    restart: always
    image: nginx:1.11.6-alpine
    ports:
      - 8080:80
      - 80:80
      - 443:443
    volumes:
      - ./conf.d:/etc/nginx/conf.d
      - ./log:/var/log/nginx
      - ./www:/var/www
      - /etc/letsencrypt:/etc/letsencrypt
```

### docker-compose命令

1. 启动:docker-compose up -d-d为守护进程
2. 查看服务进程 :docker-compose ps
3. 停止服务:docker-compose stop [name]
4. 启动服务:docker-compose start [name]
5. 删除服务:docker-compose rm [name]
6. 查看具体服务的日志:docker-compose logs -f [name]
7. 可以进入容器内部:docker-compose exec [name] shell

| 说明      | 命令                                      |
| ------- | --------------------------------------- |
| build   | 构建项目中的服务容器                              |
| help    | 获得一个命令的帮助                               |
| kill    | 通过发送SIGKILL信号来强制停止服务容器                  |
| config  | 验证和查看compose文件配置                        |
| create  | 为服务创建容器。只是单纯的create，还需要使用start启动compose |
| down    | 停止并删除容器，网络，镜像和数据卷                       |
| exec    | 在运行的容器中执行一个命令                           |
| logs    | 查看服务容器的输出                               |
| pause   | 暂停一个服务容器                                |
| port    | 打印某个容器端口所映射的公共端口                        |
| ps      | 列出项目中目前的所有容器                            |
| pull    | 拉取服务依赖的镜像                               |
| push    | 推送服务镜像                                  |
| restart | 重启项目中的服务                                |
| rm      | 删除所有（停止状态的）服务容器                         |
| run     | 在指定服务上执行一个命令                            |
| scale   | 设置指定服务运行的容器个数                           |
| start   | 启动已经存在的服务容器                             |
| stop    | 停止已经处于运行状态的容器，但不删除它                     |
| top     | 显示运行的进程                                 |
| unpause | 恢复处于暂停状态中的服务                            |
| up      | 自动完成包括构建镜像、创建服务、启动服务并关闭关联服务相关容器的一些列操作   |

参考文章:

* [https://www.cnblogs.com/pyyu/p/9485268.html](https://www.cnblogs.com/pyyu/p/9485268.html)
* [https://www.jianshu.com/p/b027c61346af](https://www.jianshu.com/p/b027c61346af)
* [https://zhuanlan.zhihu.com/p/51055141](https://zhuanlan.zhihu.com/p/51055141)
* [https://www.jianshu.com/p/93a678d1bde6](https://www.jianshu.com/p/93a678d1bde6)
