---
title: "Go Channel"
date: 2020-10-27T15:33:45+08:00
draft: false
toc: true
categories: [go]
tags: [golang]
authors:
    - haiyux
---

## 什么是channel

channels 是一种类型安全的消息队列，充当两个 goroutine 之间的管道，将通过它同步的进行任意资源的交换。chan 控制 goroutines 交互的能力从而创建了 Go 同步机制。当创建的 chan 没有容量时，称为无缓冲通道。反过来，使用容量创建的 chan 称为缓冲通道。

要了解通过 chan 交互的 goroutine 的同步行为是什么，我们需要知道通道的类型和状态。根据我们使用的是无缓冲通道还是缓冲通道，场景会有所不同，所以让我们单独讨论每个场景。

## 无缓冲管道

make ： `ch := make(chan struct{})`
无缓冲 chan 没有容量，因此进行任何交换前需要两个 goroutine 同时准备好。当 goroutine 试图将一个资源发送到一个无缓冲的通道并且没有goroutine 等待接收该资源时，该通道将锁住发送 goroutine 并使其等待。当 goroutine 尝试从无缓冲通道接收，并且没有 goroutine 等待发送资源时，该通道将锁住接收 goroutine 并使其等待。

无缓冲信道的本质是保证同步。

![](/images/2344773-20210819140249416-107141713.png)

无缓冲channel在消息发送时需要接收者就绪。声明无缓冲channel的方式是不指定缓冲大小。以下是一个列子：

```go
package main

import (
    "sync"
    "time"
)

func main() {
    c := make(chan string)

    var wg sync.WaitGroup
    wg.Add(2)

    go func() {
        defer wg.Done()
        c <- `foo`
    }()

    go func() {
        defer wg.Done()

        time.Sleep(time.Second * 1)
        println(`Message: `+ <-c)
    }()

    wg.Wait()
}
```

第一个协程会在发送消息`foo`时阻塞，原因是接收者还没有就绪：这个特性在[标准文档](https://golang.org/ref/spec?source=post_page---------------------------#Channel_types)中描述如下：

> 如果缓冲大小设置为0或者不设置，channel为无缓冲类型，通信成功的前提是发送者和接收者都处于就绪状态。

[effective Go](https://golang.org/doc/effective_go.html?source=post_page---------------------------#channels)文档也有相应的描述：

> 无缓冲channel，发送者会阻塞直到接收者接收了发送的值。

为了更好的理解channel的特性，接下来我们分析channel的内部结构。

```go
package main

import (
    "sync"
    "time"
    "fmt"
)


func main() {
    c := make(chan string)

    var wg sync.WaitGroup
    wg.Add(2)

    go func() {
        defer wg.Done()
        c <- "foo"
    }()

    go func() {
        defer wg.Done()

        time.Sleep(time.Second)
        fmt.Println("message:" + <- c)
    }()

    wg.Wait()
}
/*
foo
*/
```

## 有缓冲管道

buffered channel 具有容量，因此其行为可能有点不同。当 goroutine 试图将资源发送到缓冲通道，而该通道已满时，该通道将锁住 goroutine并使其等待缓冲区可用。如果通道中有空间，发送可以立即进行，goroutine 可以继续。当goroutine 试图从缓冲通道接收数据，而缓冲通道为空时，该通道将锁住 goroutine 并使其等待资源被发送。

![](/images/2344773-20210819140332013-249306558.png)

```go
package main

import (
    "sync"
    "time"
    "fmt"
)

func main() {
    c := make(chan string,2)

    var wg sync.WaitGroup
    wg.Add(2)

    go func(){
        defer wg.Done()

        c <- "foo"
        c <- "bar"
    }()

    go func(){
        defer wg.Done()

        time.Sleep(time.Second)
        fmt.Println("mesage:" + <- c)
        fmt.Println("message:" + <- c)
    }()

    wg.Wait()
}
/*
mesage:foo
message:bar
*/
```

## 追踪耗时

通过Go工具trace中的`synchronization blocking profile`来查看测试程序被同步原语阻塞所消耗的时间。接收时的耗时对比：无缓冲channel为9毫秒，缓冲大小为50的channel为1.9毫秒。

![](/images/2344773-20210819140357143-1327281824.png)

发送时的耗时对比：有缓冲channel将耗时缩小了五倍。

![](/images/2344773-20210819140410869-550649919.png)

- Send 先于 Receive 发生。
- 好处: 延迟更小。
- 代价: 不保证数据到达，越大的 buffer，越小的保障到达。buffer = 1 时，给你延迟一个消息的保障。

## 参考文章

- [https://www.it1352.com/807929.html](https://www.it1352.com/807929.html)
- [https://www.pengrl.com/p/21027/](https://www.pengrl.com/p/21027/)
