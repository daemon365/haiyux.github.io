---
title: "grpc基础"
date: 2020-11-29T06:33:45+08:00
draft: false
toc: true
categories: [microservice]
tags: [微服务,protobuf,grpc]
authors:
    - haiyux
---

## RPC 框架原理

RPC 框架的目标就是让远程服务调用更加简单、透明，RPC 框架负责屏蔽底层的传输方式（TCP 或者 UDP）、序列化方式（XML/Json/ 二进制）和通信细节。服务调用者可以像调用本地接口一样调用远程的服务提供者，而不需要关心底层通信细节和调用过程。

![](/img/2344773-20210820181007921-1424196285.png)

业界主流的 RPC 框架整体上分为三类：

* 支持多语言的 RPC 框架，比较成熟的有 Google 的 gRPC、facebook的Apache、Thrift；
* 只支持特定语言的 RPC 框架，例如新浪微博的 Motan；
* 支持服务治理等服务化特性的分布式服务框架，其底层内核仍然是 RPC 框架, 例如阿里的 Dubbo。

## gRPC是什么

[gRPC](http://www.oschina.net/p/grpc-framework) 是一个高性能、开源和通用的 RPC 框架，面向移动和 HTTP/2 设计。目前提供 C、Java 和 Go 语言版本，分别是：grpc, grpc-java, grpc-go. 其中 C 版本支持 C, C++, Node.js, Python, Ruby, Objective-C, PHP 和 C## 支持.

gRPC 基于 HTTP/2 标准设计，带来诸如双向流、流控、头部压缩、单 TCP 连接上的多复用请求等特。这些特性使得其在移动设备上表现更好，更省电和节省空间占用。

### grc优点

- 多语言：语言中立，支持多种语言。
- 轻量级、高性能：序列化支持 PB(Protocol Buffer)和 JSON，PB 是一种语言无关的高性能序列化框架。
  可插拔
- IDL：基于文件定义服务，通过 proto3 工具生成指定语言的数据结构、服务端接口以及客户端 Stub。
- 移动端：基于标准的 HTTP2 设计，支持双向流、消息头压缩、单 TCP 的多路复用、服务端推送等特性，这些特性使得 gRPC 在移动端设备上更加省电和节省网络流量。

![](/img/2344773-20210820181020505-827348595.png)

## 安全

HTTP2 规范当使用 TLS 时强制使用 TLS 1.2 及以上的版本，并且在部署上对允许的密码施加一些额外的限制以避免已知的比如需要 SNI 支持的问题。并且期待 HTTP2 与专有的传输安全机制相结合，这些传输机制的规格说明不能提供有意义的建议。

## gRPC使用

使用gRPC， 我们可以一次性的在一个.proto文件中定义服务并使用任何支持它的语言去实现客户端和服务端，反过来，它们可以应用在各种场景中，从Google的服务器到你自己的平板电脑—— gRPC帮你解决了不同语言及环境间通信的复杂性。使用protocol buffers还能获得其他好处，包括高效的序列号，简单的IDL以及容易进行接口更新。总之一句话，使用gRPC能让我们更容易编写跨语言的分布式代码。

* 通过一个 protocol buffers 模式，定义一个简单的带有 Hello World 方法的 RPC 服务。
* 用你最喜欢的语言(如果可用的话)来创建一个实现了这个接口的服务端。
* 用你最喜欢的(或者其他你愿意的)语言来访问你的服务端。

## 什么用grpc

- 服务而非对象、消息而非引用：促进微服务的系统间粗粒度消息交互设计理念。
- 负载无关的：不同的服务需要使用不同的消息类型和编码，例如 protocol buffers、JSON、XML 和 Thrift。
- 流：Streaming API。
- 阻塞式和非阻塞式：支持异步和同步处理在客户端和服务端间交互的消息序列。
- 元数据交换：常见的横切关注点，如认证或跟踪，依赖数据交换。
- 标准化状态码：客户端通常以有限的方式响应 API 调用返回的错误。

### HealthCheck

gRPC 有一个标准的健康检测协议，在 gRPC 的所有语言实现中基本都提供了生成代码和用于设置运行状态的功能。

主动健康检查 health check，可以在服务提供者服务不稳定时，被消费者所感知，临时从负载均衡中摘除，减少错误请求。当服务提供者重新稳定后，health check 成功，重新加入到消费者的负载均衡，恢复请求。health check，同样也被用于外挂方式的容器健康检测，或者流量检测(k8s liveness & readiness)。

![](/img/2344773-20210820181031264-435404827.png)

![](/images/2344773-20210820181043127-1801793084-0078917.png)

## protubuf文件编写

```go
syntax = "proto3";

package hello;

// option go_package = "hello";
option go_package = "/hello";

// The greeting service definition.
service Greeter {
  // Sends a greeting
  rpc SayHello (HelloRequest) returns (HelloReply)  {}
}

// The request message containing the user's name.
message HelloRequest {
  string name = 1;
}

// The response message containing the greetings
message HelloReply {
  string message = 1;
}
```

## golang创建grpc server

安装工具包:

1. 下载protoc [链接](https://www.zhaohaiyu.com/protobuf/)
2. `go install google.golang.org/protobuf/cmd/protoc-gen-go@latest`
3. `go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest`

执行:

```bash
protoc --go_out=./  --go-grpc_out=./  hello.proto
```

* --proto_path: 指定了要去哪个目录中搜索import中导入的和要编译为.go的proto文件 (在这没有使用,需要的话可以加上)
* --go_out:指定了生成的go文件的目录，我在这里把go文件放到本目录中
* --go-grpc_out: 指定了生成的go grpc文件的目录，我在这里把go grpc文件放到本目录中
* hello.proto， 定义了我要编译的文件是哪个文件。

### go server代码

```go
package main

import (
    "context"
    "errors"
    "fmt"
    "github.com/zhaohaiyu1996/akit/example/grpc/hello"
    "google.golang.org/grpc"
    "net"
)

type Server struct {
    hello.UnimplementedGreeterServer
}

// SayHello implements helloworld.GreeterServer
func (s *Server) SayHello(ctx context.Context, in *hello.HelloRequest) (*hello.HelloReply, error) {
    if in.Name == "error" {
        return nil, errors.New("123")
    }
    if in.Name == "panic" {
        panic("grpc panic")
    }
    return &hello.HelloReply{Message: fmt.Sprintf("Hello %+v", in.Name)}, nil
}

type Ss struct {
    *grpc.Server
}

func main() {
    // 监听本地的8848端口

    s := Ss{grpc.NewServer()}
    hello.RegisterGreeterServer(s, &Server{}) // 在gRPC服务端注册服务

    lis, err := net.Listen("tcp", "127.0.0.1:8808")
    if err != nil {
        fmt.Printf("listen failed: %v", err)
        return
    }
    //reflection.Register(s.Server) //在给定的gRPC服务器上注册服务器反射服务
    // Serve方法在lis上接受传入连接，为每个连接创建一个ServerTransport和server的goroutine。
    // 该goroutine读取gRPC请求，然后调用已注册的处理程序来响应它们。
    err = s.Serve(lis)
    if err != nil {
        fmt.Printf("failed to serve: %v", err)
        return
    }
}
```

## golang创建grpc client

执行:

```bash
protoc --go_out=./  --go-grpc_out=./  hello.proto
```

### go client代码

```go
package main

import (
    "context"
    "fmt"
    "github.com/zhaohaiyu1996/akit/example/grpc/hello"
    "google.golang.org/grpc"
)


func main() {
    // 连接服务器
    conn, err := grpc.Dial("localhost:8808", grpc.WithInsecure())
    if err != nil {
        fmt.Printf("connect faild: %v", err)
    }
    defer conn.Close()
    c := hello.NewGreeterClient(conn)
    // 调用SayHello
    r, err := c.SayHello(context.Background(), &hello.HelloRequest{Name: "zhaohaiyu"})
    if err != nil {
        fmt.Printf("sayHello failed: %v", err)
    }
    fmt.Println(r)
}
```

结果:

```bash
SayHello: hello ---> zhaohaiyu
```

## python创建grpc client

使用python客户端调用golang服务端的方法

下载依赖:

```python
pip install grpcio
pip install protobuf
pip install grpcio_tools
```

执行:

```bash
python -m grpc_tools.protoc -I ./ --python_out=./ --grpc_python_out=./ hello.proto
```

### python client代码

```python
import grpc
import hello_pb2
import hello_pb2_grpc
def run():
    with grpc.insecure_channel('localhost:8848') as channel:
        stub = hello_pb2_grpc.HelloStub(channel)
        res = stub.SayHello(hello_pb2.HelloRequest(name="赵海宇"))
    print(res.message)
if __name__ == '__main__':
    run()
```

结果:

```bash
python ./main.go
hello ---> 赵海宇
```

## gprc的haeder

* grpc是基于http2.0的rpc框架 -
* grpc对于http头部传递数据进行了封装 metadata,单独抽象了一个包google.golang.org/grpc/metadata-
* type ***p[string][]string其实就是一个map

客户端发送方式一:

```go
// 创建md 并加入ctx
    md := metadata.Pairs("key1","value1","key2","value2")
    ctx := metadata.NewOutgoingContext(context.Background(),md)
    // 从ctx中拿出md
    md,_ = metadata.FromOutgoingContext(ctx)
    newMd := metadata.Pairs("key3","value3")
    ctx = metadata.NewOutgoingContext(ctx,metadata.Join(md,newMd))
```

客户端发送方式二:

```go
ctx := context.Background()
ctx = metadata.AppendToOutgoingContext(ctx,"key1","value1","key2","value2")
ctx = metadata.AppendToOutgoingContext(ctx,"key3","value3")
```

服务端接收:

```go
md,ok := metadata.FromIncomingContext(ctx)
```

实例:

1. server:

```go
package main
import (
    "fmt"
    "net"
    pb "test/demo13/server/hello"
    "github.com/grpc-ecosystem/grpc-gateway/examples/clients/responsebody"
    "github.com/uber/jaeger-client-go/crossdock/client"
    "golang.org/x/net/context"
    "google.golang.org/grpc"
    "google.golang.org/grpc/metadata"
    "google.golang.org/grpc/reflection"
)
type server struct{}
func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloResponse, error) {

    md,ok := metadata.FromIncomingContext(ctx)
    if ok {
        fmt.Println(md)
    }
    return &pb.HelloResponse{Message: "hello ---> " + in.Name}, nil
}
func main() {
    // 监听本地的8848端口
    lis, err := net.Listen("tcp", "localhost:8848")
    if err != nil {
        fmt.Printf("listen failed: %v", err)
        return
    }
    s := grpc.NewServer() // 创建gRPC服务器
    pb.RegisterHelloServer(s, &server{}) // 在gRPC服务端注册服务
    reflection.Register(s) //在给定的gRPC服务器上注册服务器反射服务
    // Serve方法在lis上接受传入连接，为每个连接创建一个ServerTransport和server的goroutine。
    // 该goroutine读取gRPC请求，然后调用已注册的处理程序来响应它们。
    err = s.Serve(lis)
    if err != nil {
        fmt.Printf("failed to serve: %v", err)
        return
    }
}
```

1. client

```go
package main
import (
    "context"
    "fmt"
    pb "test/demo13/client/hello"
    "google.golang.org/grpc"
    "google.golang.org/grpc/metadata"
)
func main() {
    // 连接服务器
    conn, err := grpc.Dial("localhost:8848", grpc.WithInsecure())
    if err != nil {
        fmt.Printf("faild to connect: %v", err)
    }
    defer conn.Close()
    c := pb.NewHelloClient(conn)
    // 调用服务端的SayHello
    ctx := context.Background()
    ctx = metadata.AppendToOutgoingContext(ctx,"zhyyz","961119")
    r, err := c.SayHello(ctx, &pb.HelloRequest{Name: "zhaohaiyu"})
    if err != nil {
        fmt.Printf("sayHello failed: %v", err)
    }
    fmt.Printf("SayHello: %s \n", r.Message)
}
```
