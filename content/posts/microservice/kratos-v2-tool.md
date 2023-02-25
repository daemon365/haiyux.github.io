---
title: "kratos v2版本命令行工具使用"
date: 2021-12-26T21:05:44+08:00
draft: false
toc: true
categories: [microservice,go]
tags:
- 微服务
- kratos
authors:
    - haiyux
---

## kratos命令行工具是什么？

kratos tool 是微服务框架 [kratos](https://github.com/go-kratos/kratos) 的命令行工具，提供创建模板，编译protobuf 文件，运行项目等功能。

## 使用

### 下载

```bash
go install github.com/go-kratos/kratos/cmd/kratos/v2@latest
```

查看是否安装成功

```bash
kratos -v

kratos version v2.1.3
```

### 升级

```bash
kratos upgrade
```

## 查看帮助

```go
kratos --help
```

```
Kratos: An elegant toolkit for Go microservices.

Usage:
  kratos [command]

Available Commands:
  changelog   Get a kratos change log
  completion  generate the autocompletion script for the specified shell
  help        Help about any command
  new         Create a service template
  proto       Generate the proto files
  run         Run project
  upgrade     Upgrade the kratos tools

Flags:
  -h, --help      help for kratos
  -v, --version   version for kratos

Use "kratos [command] --help" for more information about a command.
```

## new命令

kratos new 命令为创建一个kratos项目

参数：

- `-r` repo地址 默认为`https://github.com/go-kratos/kratos-layout`

- `-b` git版本 默认为main分支

- `-t` 超时时间 默认为60s

- 也可添加环境变量`KRATOS_LAYOUT_REPO` 知道远程repo

创建一个项目

```go
kratos new helloworld
```

因为默认远程仓库地址是 github上的，在国内很容易创建失败，所以要需要设置终端或者git代理（什么是终端代理和git代理可以百度或者google一下）。

当然你也可以使用`-r` 知道国内仓库 我们提供一个国内镜像`https://gitee.com/go-kratos/kratos-layout`。

如果嫌弃每次都要`-r`指定麻烦，也可以把`KRATOS_LAYOUT_REPO=https://gitee.com/go-kratos/kratos-layout` 加入到path中。

```bash
kratos new helloworld -r https://gitee.com/go-kratos/kratos-layout
```

## proto命令

proto命令下有 `add` `client` 和 `server`子命令

### add

`kratos proto add` 为创建一个proto模板

```bash
kratos proto add api/helloworld/v2/hello.proto
```

在目录`api/helloworld/v2` 下可以看到生成的文件

```protobuf
syntax = "proto3";

package api.helloworld.v2;

option go_package = "helloworld/api/helloworld/v2;v2";
option java_multiple_files = true;
option java_package = "api.helloworld.v2";

service Hello {
    rpc CreateHello (CreateHelloRequest) returns (CreateHelloReply);
    rpc UpdateHello (UpdateHelloRequest) returns (UpdateHelloReply);
    rpc DeleteHello (DeleteHelloRequest) returns (DeleteHelloReply);
    rpc GetHello (GetHelloRequest) returns (GetHelloReply);
    rpc ListHello (ListHelloRequest) returns (ListHelloReply);
}

message CreateHelloRequest {}
message CreateHelloReply {}

message UpdateHelloRequest {}
message UpdateHelloReply {}

message DeleteHelloRequest {}
message DeleteHelloReply {}

message GetHelloRequest {}
message GetHelloReply {}

message ListHelloRequest {}
message ListHelloReply {}
```

### client

`kratos proto client` 为生成 Proto 代码

使用这个命令需要下载 protobuf 工具 protoc，可以在官网下载对应版本 [Protobuf release版本](https://github.com/protocolbuffers/protobuf/releases)

```bash
kratos proto client api/helloworld/v2/
```

这条命令就可以编译`api/helloworld/v2/`下的所有`.proto`文件

如果我们需要 import 其他`proto`文件 可以在命令后面加上`protoc`的参数

比如

```bash
kratos proto client api/helloworld/v2/ --proto_path=api/helloworld/v2
```

默认也会把 `./third_party` 下import 进来 需要第三方的proto文件 可以放在这里

### server

`kratos proto server`为指定proto文件生成简单的service代码

参数：

- `-t` 生成代码的位置 默认是`internal/service`

比如

```bash
kratos proto server api/helloworld/v2/hello.proto -t=internal/service/hello
```

生成的代码

```go
package service

import (
    "context"

    pb "helloworld/api/helloworld/v2"
)

type HelloService struct {
    pb.UnimplementedHelloServer
}

func NewHelloService() *HelloService {
    return &HelloService{}
}

func (s *HelloService) ListHello(ctx context.Context, req *pb.ListHelloRequest) (*pb.ListHelloReply, error) {
    return &pb.ListHelloReply{}, nil
}
```

## run命令

启动服务

```bash
kratos run
```
