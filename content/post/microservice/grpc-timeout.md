---
title: "grpc超时控制"
date: 2021-05-24T15:13:11+08:00
draft: false
toc: true
categories: [microservice]
tags: [微服务,protobuf,grpc]
authors:
    - haiyux
---

## 什么是超时控制？

超时控制，使我们的服务之间调用可以快速抛错。比如API接口设置1s超时API调用A服务用了500ms，服务A调用和服务B用了600ms，n那么现在已经超时，还要调用服务C等等，再返回超时错误吗？这回事使服务C后面的链路做了无用功，浪费服务器资源。

![](/images/2344773-20210823145415472-1109853403.png)

## GRPC的截止时间

截止时间以请求开始的绝对时间来表示（即使 API 将它们表示为持续时间偏移），并且应 用于多个服务调用。发起请求的应用程序设置截止时间，整个请求链需要在截止时间之前 进行响应。 gRPC API 支持为 RPC 使用截止时间，出于多种原因，在 gRPC 应用程序中使 用截止时间始终是一种最佳实践。由于 gRPC 通信是在网络上发生的，因此在 RPC 和响应 之间会有延迟。另外，在一些特定的场景中， gRPC 服务本身可能要花费更多的时间来响 应，这取决于服务的业务逻辑。如果客户端应用程序在开发时没有指定截止时间，那么它 们会无限期地等待自己所发起的 RPC 请求的响应，而资源都会被正在处理的请求所占用。 这会让服务和客户端都面临资源耗尽的风险，增加服务的延迟，甚至可能导致整个 gRPC 服务崩溃。

客户端应用程序的截止时间设置为 50 毫秒（截止时间 = 当前时间 + 偏移量）。客户端和 ProductMgt 服务之间的网络延迟为 0 毫秒， ProductMgt 服务的处理延迟为 20 毫秒。 商 品管理服务（ ProductMgt 服务）必须将截止时间的偏移量设置为 30 毫秒。 因为库存服 务（ Inventory 服务）需要 30 毫秒来响应， 所以截止时间的事件会在两个客户端上发生 （ ProductMgt 调用 Inventory 服务和客户端应用程序）。

ProductMgt 服务的业务逻辑将延迟时间增加了 20 毫秒。 随后， ProductMgt 服务的调用逻 辑触发了超出截止时间的场景，并且传播回客户端应用程序。因此，在使用截止时间时， 要明确它们适用于所有服务场景。


![](/images/2344773-20210823145426449-660260946.png)

```go
conn, err := grpc.Dial(address, grpc.WithInsecure()) 
if err != nil { 
  log.Fatalf("did not connect: %v", err) 
} 
defer conn.Close() 
client := pb.NewOrderManagementClient(conn)

clientDeadline := time.Now().Add( time.Duration(2 * time.Second)) 
ctx, cancel := context.WithDeadline(context.Background(), clientDeadline)
defer cancel()

// 调用方法传入ctx
```
