---
title: "Nginx基础"
date: 2020-06-13T18:30:43+08:00
draft: false
toc: true
categories: [operations]
tags: [运维,nginx]
authors:
    - haiyux
---

## nginx是什么

nginx是一个开源的，支持高性能，高并发的www服务和代理服务软件。

*   支持高并发，能支持几万并发连接

*   资源消耗少，在3万并发连接下开启10个nginx线程消耗的内存不到200M

*   可以做http反向代理和负载均衡

*   支持异步网络i/o事件模型epoll

![](/images/2344773-20210819233627191-1981392114.png)

Tengine是由淘宝网发起的Web服务器项目。它在Nginx的基础上，针对大访问量网站的需求，添加了很多高级功能和特性。T目标是打造一个高效、稳定、安全、易用的Web平台。

## 安装环境依赖包

```bash
yum install gcc-c++ pcre pcre-devel zlib zlib-devel gcc patch libffi-devel python-devel  zlib-devel bzip2-devel openssl-devel ncurses-devel sqlite-devel readline-devel tk-devel gdbm-devel db4-devel libpcap-devel xz-devel openssl openssl-devel -y
```

## 安装并启动nginx

1.  下载源码包 `http://tengine.taobao.org/download/tengine-2.3.3.tar.gz`

2.  解压缩源码 `tar -zxvf tengine-2.3.3.tar.gz`配置

3.  编译安装 开启nginx状态监测功能

    1. `./configure`
    2. `make && make install`

1.  nginx操作，进入nginx下的sbin目录（默认在`/usr/local下`）

    *   启动`./nginx -c`指定配置文件
*   关闭`./nginx -s stop`
    *   重新加载`./nginx -s reload`
*   检查配置文件 `./nginx -t`

## 部署一个web站点

nginx默认站点是Nginx目录下的html文件夹，这里可以从nginx.conf中查到

```nginx
location / {
            root   html; # 这里是默认的站点html文件夹，也就是 /usr/local/nginx/html 文件夹下的内容
            index  index.html index.htm; # 站点首页文件名是index.html
        }
```

如果要部署网站业务数据，只需要把开发好的程序全放到html目录下即可

```bash
[root@VM-0-3-centos html]# ls /usr/local/nginx/html/
50x.html  index.html
```

因此只需要通过域名/资源，即可访问

```http
http://a.zhaohaoyu.com
```

## Nginx的目录结构

```bash
client_body_temp  conf  fastcgi_temp  html  logs  proxy_temp  sbin  scgi_temp  static  uwsgi_temp
```

*   conf 存放nginx所有配置文件的目录,主要nginx.conf

*   html 存放nginx默认站点的目录，如index.html、error.html等

*   logs 存放nginx默认日志的目录，如error.log access.log

*   sbin 存放nginx主命令的目录,./nginx

## Nginx主配置文件解析

Nginx主配置文件/etc/nginx/nginx.conf是一个纯文本类型的文件，整个配置文件是以区块的形式组织的。一般，每个区块以一对大括号{}来表示开始与结束。

1.  ### CoreModule核心模块

    *   `user www`  Nginx进程所使用的用户

    *   `worker_processes 1`; Nginx运行的work进程数量(建议与CPU数量一致或auto)

    *   `error_log  logs/error.log` Nginx错误日志存放路径

    *   `pid logs/nginx.pid` Nginx服务运行后产生的pid进程号

1. ### events事件模块

   ```nginx
   events {
       worker_connections  1024; # 每个worker进程支持的最大连接数  
       use epool; # 事件驱动模型, epoll默认
   }
   ```

1. ### http内核模块

   ```nginx
   # 公共的配置定义在http
   http {
       # http层开始 ...
       include       mime.types;
       default_type  application/octet-stream;
       
       access_log  logs/access.log  main; # 访问日志
       
       # 使用Server配置网站, 每个Server{}代表一个网站(简称虚拟主机)
       server {
           listen       80; # 监听端口, 默认80 
           server_name  localhost; # 提供服务的域名或主机名
       
           location / {
               root   html; # 存放网站代码路径
               index  index.html index.htm; # 服务器返回的默认页面文件
           }
   				
       		# 指定错误代码, 统一定义错误页面, 错误代码重定向到新的Locaiton
           error_page   500 502 503 504  /50x.html; 
           location = /50x.html {
               root   html;
           }                                                                                                                                          }
   ```

1.  ### include

    *   当存在多个域名时，如果所有配置都写在 nginx.conf 主配置文件中，难免会显得杂乱与臃肿。为了方便配置文件的维护，所以需要进行拆分配置。

        ```nginx
        # 在nginx.conf中 加入  include a.zhaohaiyu.com/nginx.conf; 
        # 在a.zhaohaiyu.com/nginx.conf中加入 
        server {  
        		listen 8000;  
        		server_name test2.com; 
            
        		location / {  
        				proxy_set_header Host $host:$server_port;  
        				proxy_set_header X-Real-Ip $remote_addr; 
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; 
                ## proxy_pass 				   http://xxx.xxx.xxx;  echo "test2.com"; ## 输出测试   
             } 
         } 
        # 等于把zhaohaiyu.com/nginx.conf直接吸入nginx.conf中
        ```

## Nginx虚拟主机

![](/images/2344773-20210819233653285-66968672.png)

如果每台linux服务器只运行了一个小网站，那么人气低，流量小的草根站长需要承担高额的服务器租赁费，也造成了硬件资源浪费。

虚拟主机就是将一台服务器分割成多个“虚拟服务器”，每个站点使用各自的硬盘空间，由于省资源，省钱，众多网站都使用虚拟主机来部署网站。

虚拟主机的概念就是在web服务里的一个独立的网站站点，这个站点对应独立的域名（IP），具有独立的程序和资源目录，可以独立的对外提供服务。 这个独立的站点配置是在nginx.conf中使用server{}代码块标签来表示一个虚拟主机。 Nginx支持多个server{}标签，即支持多个虚拟主机站点。

## nginx status

### 启用nginx status配置

在默认主机里面加上location或者你希望能访问到的主机里面。

```nginx
server {  
  stub_status on; 
}
```

### 重启nginx

请依照你的环境重启你的nginx

`./ngnix -s reload`

### 打开status页面

![](/images/2344773-20210819233710510-190471692.png)

### nginx status

*   `active connections `– 活跃的连接数量

*   `server accepts handled requests `— 总共处理了11989个连接 , 成功创建11989次握手, 总共处理了11991个请求

*   `reading` — 读取客户端的连接数.

*   `writing` — 响应数据到客户端的数量

*   `waiting` — 开启 keep-alive 的情况下,这个值等于 active – (reading+writing), 意思就是 Nginx 已经处理完正在等候下一次请求指令的驻留连接.

## Nginx代理

![](/images/2344773-20210819233724929-688371710.png)

### 正向代理

**正向代理，也就是传说中的代理,他的工作原理就像一个跳板（VPN），简单的说：**

**我是一个用户，我访问不了某网站，但是我能访问一个代理服务器，这个代理服务器呢，他能访问那个我不能访问的网站，于是我先连上代理服务器，告诉他我需要那个无法访问网站的内容，代理服务器去取回来，然后返回给我。**

![](/images/2344773-20210819233734937-920215579.png)

### 反向代理

**对于客户端而言，代理服务器就像是原始服务器。**

![](/images/2344773-20210819233748014-1958850697.png)

nginx实现负载均衡的组件

```nginx
ngx_http_proxy_module    # proxy代理模块，用于把请求抛给服务器节点或者upstream服务器池
```

### 实现一个简单的反向代理

机器准备，两台服务器

```nginx
master  192.168.11.63　　主负载 slave   192.168.11.64　　web1
```

主负载均衡节点的配置文件

```nginx
worker_processes  1; 
error_log logs/error.log; pid       
logs/nginx.pid; 

events {  
		worker_connections 1024; 
} 

http {  
		include       mime.types;  
		default_type application/octet-stream;  
		log_format main '$remote_addr - $remote_user [$time_local] "$request" '  '$status $body_bytes_sent "$http_referer" '  '"$http_user_agent" "$http_x_forwarded_for"';  
		access_log logs/access.log main;  
		sendfile       on;  
		keepalive_timeout 65;  
		upstream slave_pools {  
				server 192.168.11.64:80 weight=1;
    }
    
    server {  
				listen       80;  
				server_name localhost;  
				location / {  
						proxy_pass http://slave_pools;  
						root   html;  
						index index.html index.htm;  
				}  
		error_page   500 502 503 504 /50x.html;  
		location = /50x.html {  
		root   html;  
		}  
	}
}
```

检查语法并启动nginx

```
[root@master 192.168.11.63 /opt/nginx1-12]$./nginx -t 
nginx: the configuration file /opt/nginx1-12/conf/nginx.conf syntax is ok nginx: configuration file /opt/nginx1-12/conf/nginx.conf test is successful 
#启动nginx 
[root@master 192.168.11.63 /opt/nginx1-12]$/./nginx 
#检查端口 
[root@master 192.168.11.63 /opt/nginx1-12]$netstat -tunlp|grep nginx tcp       
0     0 0.0.0.0:80             0.0.0.0:*               LISTEN     8921/nginx: master
```

此时访问master的服务器192.168.11.63:80地址，已经会将请求转发给slave的80端口

除了页面效果的展示以外，还可以通过log(access.log)查看代理效果

master端日志

![](/images/2344773-20210819233802753-442727988.png)

slave端日志

![](/images/2344773-20210819233811667-646303470.png)

## LOCALTION

### Location语法优先级排列

**匹配符 匹配规则 优先级**

*   = 精确匹配 1

*   ^~ 以某个字符串开头 2

*   ~ 区分大小写的正则匹配 3

*   ~* 不区分大小写的正则匹配 4

*   !~ 区分大小写不匹配的正则 5

*   !~* 不区分大小写不匹配的正则 6

*   / 通用匹配，任何请求都会匹配到 7

### nginx.conf配置文件实例

```nginx
server {  
		listen 80;  
		server_name pythonav.cn;   #优先级1,精确匹配，根路径  
		location =/ {  
				return 400;  
		}   #优先级2,以某个字符串开头,以av开头的，优先匹配这里，区分大小写  
		location ^~ /av {  
				root /data/av/;  
		}   #优先级3，区分大小写的正则匹配，匹配/media*****路径  
		location ~ /media {  
				alias /data/static/;  
		}   #优先级4 ，不区分大小写的正则匹配，所有的****.jpg|gif|png 都走这里  
		location ~* .*\.(jpg|gif|png|js|css)$ {  
				root /data/av/;  
		}   #优先7，通用匹配  
		location / {  
				return 403;  
		} 
}
```

### nginx语法之root和alias区别实战

**nginx指定文件路径有root和alias两种方法** 区别在方法和作用域：

1.  方法：

    *   root 语法 root 路径; 默认值 root html; 配置块 http{} server {} location{}

    *   alias 语法： alias 路径 配置块 location{}

root和alias区别在nginx如何解释location后面的url，这会使得两者分别以不同的方式讲请求映射到服务器文件上

root参数是root路径+location位置

root实例：

```
location ^~ /av {  root /data/av;   注意这里可有可无结尾的   / }
```

请求url是zhaohaiyu.com/av/index.html时 web服务器会返回服务器上的/data/av/av/index.html

root实例2：

```
location ~* .*\.(jpg|gif|png|js|css)$ {  root /data/av/; }
```

请求url是zhaohaiyu.com/girl.gif时 web服务器会返回服务器上的/data/static/girl.gif

alias实例：

*   alias参数是使用alias路径替换location路径 alias是一个目录的别名 注意alias必须有 "/" 结束！ alias只能位于location块中

```
location ^~ /av {  alias /data/static/; }
```

请求url是zhaohaiyu.com/av/index.html时 web服务器会返回服务器上的/data/static/index.html

## Keepalived高可用软件

什么是keepalived

*   Keepalived是一个用C语言编写的路由软件。该项目的主要目标是为Linux系统和基于Linux的基础架构提供简单而强大的负载均衡和高可用性设施。 还可以作为其他服务（nginx，mysql）的高可用软件 keepalived主要通过vrrp协议实现高可用功能。vrrp叫（virtual router redundancy protocol）虚拟路由器冗余协议，目的为了解决单点故障问题，他可以保证个别节点宕机时。整个网络可以不间断的运行。

高可用故障切换原理

*   在keepalived工作时，主master节点会不断的向备节点发送心跳消息，告诉备节点自己还活着， 当master节点故障时，就无法发送心跳消息，备节点就无法检测到来自master的心跳了，于是调用自身的接管程序，接管master节点的ip资源以及服务， 当master主节点恢复时，备backup节点又会释放接管的ip资源和服务，回复到原本的备节点角色。

1.  硬件环境准备

*   实验环境应该最好是4台虚拟机，环境有限因此用2台机器

    1.  master

    2.  slave

```nginx
global_defs {
  notification_email {
    eric.k.zhang@ericsson.com
  }
  notification_email_from keepalived@node-10-210-149-21
  smtp_server 127.0.0.1
  smtp_connect_timeout 30
  router_id LVS_DEVEL
}


vrrp_script check_webproxy {
  script "killall -0 nginx"
  interval 1
  weight 21
}

vrrp_script check_mantaince_down {
  script "[[ -f /etc/keepalived/down ]] && exit 1 || exit 0"
  interval 1
  weight 2
}


vrrp_instance vip_10_210_149_23 {
  state MASTER
  interface ens192
  virtual_router_id 23
  garp_master_delay 1
  mcast_src_ip 10.210.149.21
  lvs_sync_daemon_interface ens192
  priority 110
  advert_int 2
  authentication {
    auth_type PASS
    auth_pass 1111
  }
  track_interface {
    ens192
  }
  virtual_ipaddress {
    10.210.149.23/24 dev ens192 label ens192:0
  }
  track_script {
    check_webproxy
    check_mantaince_down
  }
}

vrrp_instance nginx_vip_10_210.149_24 {
  state BACKUP
  interface ens192
  virtual_router_id 24
  garp_master_delay 1
  mcast_src_ip 10.210.149.21
  lvs_sync_daemon_interface ens192
  priority 100
  advert_int 2
  authentication {
    auth_type PASS
    auth_pass 1111
  }
  track_interface {
    ens192
  }
  virtual_ipaddress {
    10.210.149.24/24 dev ens192 label ens192:1
  }
  track_script {
    check_webproxy
    check_mantaince_down
  }
}
```

```nginx
global_defs {
  notification_email {
    eric.k.zhang@ericsson.com
  }
  notification_email_from keepalived@node-10-210-149-21
  smtp_server 127.0.0.1
  smtp_connect_timeout 30
  router_id LVS_DEVEL
}


vrrp_script check_webproxy {
  script "killall -0 nginx"
  interval 1
  weight 21
}

vrrp_script check_mantaince_down {
  script "[[ -f /etc/keepalived/down ]] && exit 1 || exit 0"
  interval 1
  weight 2
}


vrrp_instance vip_10_210_149_23 {
  state BACKUP
  interface ens192
  virtual_router_id 23
  garp_master_delay 1
  mcast_src_ip 10.210.149.22
  lvs_sync_daemon_interface ens192
  priority 100
  advert_int 2
  authentication {
    auth_type PASS
    auth_pass 1111
  }
  track_interface {
    ens192
  }
  virtual_ipaddress {
    10.210.149.23/24 dev ens192 label ens192:0
  }
  track_script {
    check_webproxy
    check_mantaince_down
  }
}

vrrp_instance nginx_vip_10_210.149_24 {
  state MASTER
  interface ens192
  virtual_router_id 24
  garp_master_delay 1
  mcast_src_ip 10.210.149.22
  lvs_sync_daemon_interface ens192
  priority 110
  advert_int 2
  authentication {
    auth_type PASS
    auth_pass 1111
  }
  track_interface {
    ens192
  }
  virtual_ipaddress {
    10.210.149.24/24 dev ens192 label ens192:1
  }
  track_script {
    check_webproxy
    check_mantaince_down
  }
}
```