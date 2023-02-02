---
title: "RabbitMQ消息队列"
date: 2021-07-01T17:40:39+08:00
draft: false
toc: true
categories: [database]
tags: [mq]
authors:
    - haiyux
---



## 消息队列

本篇文章主要介绍了 RabbitMQ 这种消息队列，从消息队列的概念、应用场景、安装方式到它的核心概念、五种工作模式。在安装的时候推荐使用 Docker 方式进行安装。重点需要理解的就是消息队列的应用场景、核心概念和 RabbitMQ 的五种工作模式，其中用的比较多的就是发布订阅模式、主题模式。

队列 (Queue) 是一种常见的数据结构，其最大的特性就是先进先出(Firist In First Out)，作为最基础的数据结构，队列应用很广泛，比如我们熟知的 Redis 基础数据类型 List，其底层数据结构就是队列。

消息队列 (Messaeg Queue) 是一种使用队列 (Queue) 作为底层存储数据结构，可用于解决不同进程与应用之间通讯的分布式消息容器，也称为消息中间件。

目前使用得比较多的消息队列有 ActiveMQ，RabbitMQ，Kafka，RocketMQ 等。本文主要讲述的是 RabbitMQ，RabbitMQ 是用 Erlang 语言开发的一个实现了 AMQP 协议的消息队列服务器，相比其他同类型的消息队列，最大的特点在保证可观的单机吞吐量的同时，延时方面非常出色。

RabbitMQ 支持多种客户端，比如：GO、Python、Ruby、.NET、Java、JMS、C、PHP、ActionScript、XMPP、STOMP 等。

> AMQP，即 Advanced Message Queuing Protocol，高级消息队列协议，是应用层协议的一个开放标准，为面向消息的中间件设计，它是一种应用程序之间的通信方法，消息队列在分布式系统开发中应用非常广泛。这里是 AMQP 官网 [amqp.org](https://amqp.org/)

消息队列使用广泛，其应用场景有很多，下面我们列举比较常见的四个场景：

### 1、消息通讯

消息队列最主要功能收发消息，其内部有高效的通讯机制，因此非常适合用于消息通讯。

我们可以基于消息队列开发点对点聊天系统，也可以开发广播系统，用于将消息广播给大量接收者。

### 2、异步处理

一般我们写的程序都是顺序执行 (同步执行)，比如一个用户注册函数，其执行顺序如下：

- 1、写入用户注册数据。
- 2、发送注册邮件。
- 3、发送注册成功的短信通知。
- 4、更新统计数据。

按照上面的执行顺序，要全部执行完毕，才能返回成功，但其实在第 1 步执行成功后，其他的步骤完全可以异步执行，我们可以将后面的逻辑发给消息队列，再由其他程序异步执行。使用消息队列进行异步处理，可以更快地返回结果，加快服务器的响应速度，提升了服务器的性能。

### 3、服务解耦

在我们的系统中，应用与应用之间的通讯是很常见的，一般我们应用之间直接调用，比如说应用 A 调用应用 B 的接口，这时候应用之间的关系是强耦合的。

如果应用 B 处于不可用的状态，那么应用 A 也会受影响。

在应用 A 与应用 B 之间引入消息队列进行服务解耦，如果应用 B 挂掉，也不会影响应用 A 的使用。

### 4、流量削峰

对于高并发的系统来说，在访问高峰时，突发的流量就像洪水般向应用系统涌过来，尤其是一些高并发写操作，随时会导致数据库服务器瘫痪，无法继续提供服务。

而引入消息队列则可以减少突发流量对应用系统的冲击。消息队列就像水库一样，拦蓄上游的洪水，削减进入下游河道的洪峰流量，从而达到减免洪水灾害的目的。而在旱季水流量小的时候又可以把水放出来灌溉庄稼。

这方面最常见的例子就是秒杀系统，一般秒杀活动瞬间流量很高，如果流量全部涌向秒杀系统，会压垮秒杀系统，通过引入消息队列，可以有效缓冲突发流量，达到削峰填谷的作用。

## 安装

Docker 安装方式如下：

```shell
docker run -d --name rabbitmq -p 5672:5672 -p 15672:15672 rabbitmq:3-management
```

RabbitMQ 有属于自己的一套核心概念，对这些概念的理解很重要，只有理解了这些核心概念，才有可能建立对 RabbitMQ 的全面理解：

## RabbitMQ核心概念

### Broker

Broker 概念比较简单，我们可以把 Broker 理解为一个 RabitMQ Server。

### Producer 与 Consumer

生产者与消费者相对于 RabbitMQ 服务器来说，都是 RabbitMQ 服务器的客户端。

- 生产者 (Producer)：连到 RabbitMQ 服务器，将消息发送到 RabbitMQ 服务器的队列，是消息的发送方。
- 消费者 (Consumer)：连接到 RabbitMQ 则是为了消费队列中的消息，是消息的接收方。

生产者与消费者一般由我们的应用程序充当。

### Connection

Connection 是 RabbitMQ 内部对象之一，用于管理每个到 RabbitMQ 的 TCP 网络连接。

### Channel

Channel 是我们与 RabbitMQ 打交道的最重要的一个接口，我们大部分的业务操作是在 Channel 这个接口中完成的，包括定义 Queue、定义 Exchange、绑定 Queue 与 Exchange、发布消息等。

### Exchnage

消息交换机，作用是接收来自生产者的消息，并根据路由键转发消息到所绑定的队列。

生产者发送上的消息，就是先通过 Exchnage 按照绑定 (binding) 规则转发到队列的。

交换机类型 (Exchange Type) 有四种：fanout、direct、topic，headers，其中 headers 并不常用。

- fanout：这种类型不处理路由键 (RoutingKey)，很像子网广播，每台子网内的主机都获得了一份复制的消息，发布 / 订阅模式就是指使用 fanout 交换机类型，fanout 类型交换机转发消息是最快的。
- direct：模式处理路由键，需要路由键完全匹配的队列才能收到消息，路由模式使用的是 direct 类型的交换机。
- topic：将路由键和某模式进行匹配。主题模式使用的是 topic 类型的交换机。

> 路由模式，发布订阅模式，主题模式，这些工作模式我们下面会讲。

![](/images/2344773-20210831204812094-100711979.png)

### Queue

Queue 即队列，RabbitMQ 内部用于存储消息的对象，是真正用存储消息的结构，在生产端，生产者的消息最终发送到指定队列，而消费者也是通过订阅某个队列，达到获取消息的目的。

### Binding

Binding 是一种操作，其作用是建立消息从 Exchange 转发到 Queue 的规则，在进行 Exchange 与 Queue 的绑定时，需要指定一个 BindingKey，Binding 操作一般用于 RabbitMQ 的路由工作模式和主题工作模式。

> BindingKey 的概念，下面在讲 RabbitMQ 的工作模式会详细讲解。

### Virtual Host

Virutal host 也叫虚拟主机，一个 VirtualHost 下面有一组不同 Exchnage 与 Queue，不同的 Virtual host 的 Exchnage 与 Queue 之间互相不影响。应用隔离与权限划分，Virtual host 是 RabbitMQ 中最小颗粒的权限单位划分。

如果要类比的话，我们可以把 Virtual host 比作 MySQL 中的数据库，通常我们在使用 MySQL 时，会为不同的项目指定不同的数据库，同样的，在使用 RabbitMQ 时，我们可以为不同的应用程序指定不同的 Virtual host。

![](/images/2344773-20210831204825620-1555860091.png)

请参考：[www.rabbitmq.com/getstarted.…](https://www.rabbitmq.com/getstarted.html)

## 简单 (simple) 模式

simple 模式，是 RabbitMQ 几种模式中最简单的一种模式，其结构如下图所示：

![](/images/2344773-20210831204837630-909133777.png)

从上面的示意图，我们可以看出`simple`模式有以下几个特征：

- 只有一个生产者、一个消费者和一个队列。
- 生产者和消费者在发送和接收消息时，只需要指定队列名，而不需要指定发送到哪个 Exchange，RabbitMQ 服务器会自动使用 Virtual host 的默认的 Exchange，默认 Exchange 的 type 为 direct。

```go
package main

// 引入amqo包
import (
	"fmt"
	"github.com/streadway/amqp"
	"log"
)

const (
	LOGIN string = "zhaohaiyu"
	PASSWORD string = "zhy.1996"
	HOST string = "127.0.0.1"
	PORT string = "5672"
	VIRTUALHOST string = "/"
)

func Pushlish() {
	// 创建链接
	url := fmt.Sprintf("amqp://%s:%s@%s:%s%s", LOGIN, PASSWORD, HOST, PORT, VIRTUALHOST)
	conn, err := amqp.Dial(url)
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()
	// 打开一个通道
	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()
	// 生成一个交换机（交换机不存在的情况下）
	err = ch.ExchangeDeclare("test","direct", true,false,false, false, nil)
	failOnError(err, "Failed to declare an exchange")
	// 生成一个队列队列（队列不存在的情况下）
	_, err = ch.QueueDeclare("test1", true, false, false, false, nil)
	failOnError(err, "Failed to declare an queue")
	//列队与交换机绑定
	err = ch.QueueBind("test1", "zhaohaiyu", "test", false, nil)
	failOnError(err, "Bind queue to exchange failure")
	//指定交换机发布消息
	err = ch.Publish("test", "zhaohaiyu", false, false,
		amqp.Publishing{
			ContentType: "text/plain",
			Body:        []byte("生产者测试1"),
		})
	failOnError(err, "Message publish failure")
}

func Get() {
	// 创建链接
	url := fmt.Sprintf("amqp://%s:%s@%s:%s%s", LOGIN, PASSWORD, HOST, PORT, VIRTUALHOST)
	conn, err := amqp.Dial(url)
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()
	// 打开一个通道
	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()
	// 指定队列获取消息
	msg, ok, err := ch.Get("test1", true)
	failOnError(err, "Message empty")
	fmt.Println(string(msg.Body), ok)
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func main() {
	Pushlish()
	Get()
}

/*
结果：产者测试1 true
*/
```

## 工作 (work) 模式

在 simple 模式下只有一个生产者和消费者，当生产者生产消息的速度大于消费者的消费速度时，我们可以添加一个或多个消费者来加快消费速度，这种在 simple 模式下增加消费者的模式，称为 work 模式，如下图所示：

![](/images/2344773-20210831204900546-1642653585.png)

work 模式有以下两个特征：

- 可以有多个消费者，但一条消息只能被一个消费者获取。
- 发送到队列中的消息，由服务器平均分配给不同消费者进行消费

```go
package main

// 引入amqo包
import (
	"fmt"
	"github.com/streadway/amqp"
	"log"
	"time"
)

const (
	LOGIN string = "zhaohaiyu"
	PASSWORD string = "zhy.1996"
	HOST string = "127.0.0.1"
	PORT string = "5672"
	VIRTUALHOST string = "/"
)

func Pushlish() {
	// 创建链接
	url := fmt.Sprintf("amqp://%s:%s@%s:%s%s", LOGIN, PASSWORD, HOST, PORT, VIRTUALHOST)
	conn, err := amqp.Dial(url)
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()
	// 打开一个通道
	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()
	// 生成一个交换机（交换机不存在的情况下）
	err = ch.ExchangeDeclare("test","direct", true,false,false, false, nil)
	failOnError(err, "Failed to declare an exchange")
	// 生成一个队列队列（队列不存在的情况下）
	_, err = ch.QueueDeclare("test1", true, false, false, false, nil)
	failOnError(err, "Failed to declare an queue")
	//列队与交换机绑定
	err = ch.QueueBind("test1", "zhaohaiyu", "test", false, nil)
	failOnError(err, "Bind queue to exchange failure")
	//指定交换机发布消息
	for {
		time.Sleep(time.Second)
		err = ch.Publish("test", "zhaohaiyu", false, false,
			amqp.Publishing{
				ContentType: "text/plain",
				Body:        []byte("生产者测试1"),
			})
		failOnError(err, "Message publish failure")
	}
}

func Get1() {
	// 创建链接
	url := fmt.Sprintf("amqp://%s:%s@%s:%s%s", LOGIN, PASSWORD, HOST, PORT, VIRTUALHOST)
	conn, err := amqp.Dial(url)
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()
	// 打开一个通道
	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()
	// 指定队列获取消息
	for {
		time.Sleep(time.Second)
		msg, ok, err := ch.Get("test1", true)
		failOnError(err, "Message empty")
		fmt.Println("Get1", string(msg.Body), ok)
	}
}

func Get2() {
	// 创建链接
	url := fmt.Sprintf("amqp://%s:%s@%s:%s%s", LOGIN, PASSWORD, HOST, PORT, VIRTUALHOST)
	conn, err := amqp.Dial(url)
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()
	// 打开一个通道
	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()
	// 指定队列获取消息
	for {
		time.Sleep(time.Second)
		msg, ok, err := ch.Get("test1", true)
		failOnError(err, "Message empty")
		fmt.Println("Get2", string(msg.Body), ok)
	}
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func main() {
	go Pushlish()

	go Get1()
	go Get2()
	time.Sleep(time.Second * 20)
}

/*
结果：Get1  false
Get2 生产者测试1 true
Get2  false
Get1 生产者测试1 true
Get1  false
Get2 生产者测试1 true
Get2  false
Get1 生产者测试1 true
Get1 生产者测试1 true
Get2  false
Get2  false
Get1 生产者测试1 true
Get2  false
Get1 生产者测试1 true
Get2  false
Get1 生产者测试1 true
Get1 生产者测试1 true
Get2  false
Get2  false
Get1 生产者测试1 true
Get1 生产者测试1 true
Get2  false
Get1 生产者测试1 true
Get2  false
Get2  false
Get1 生产者测试1 true
Get2  false
Get1 生产者测试1 true
Get1 生产者测试1 true
Get2  false
Get1 生产者测试1 true
Get2  false
Get2 生产者测试1 true
Get1  false
Get2  false
Get1 生产者测试1 true
Get1 生产者测试1 true
Get2  false
*/
```

## 发布 / 订阅 (pub/sub) 模式

work 模式可以将消息转到多个消费者，但每条消息只能由一个消费者获取，如果我们想一条消息可以同时给多个消费者消费呢？

这时候就需要发布 / 订阅模式，其示意图如下所示：

![](/images/2344773-20210831204915962-214286316.png)

从上面的示意图我们可以看出来，在发布 / 订阅模式下，需要指定发送到哪个 Exchange 中，上面图中的 X 表示 Exchange。

- 发布 / 订阅模式中，Echange 的 type 为 fanout。
- 生产者发送消息时，不需要指定具体的队列名，Exchange 会将收到的消息转发到所绑定的队列。
- 消息被 Exchange 转到多个队列，一条消息可以被多个消费者获取。

在上图中，oneQueue 中的消息要么被 CustomerA 获取，要么被 CustomerB 获取。也就是同一条消息，要么是 CustomerA + CustomerC 消费、要么是 CustomerB + CustomerC 消费。

生产者：

```go
package main

import (
	"fmt"
	"github.com/streadway/amqp"
	"log"
	"os"
	"strings"
)

const (
	LOGIN string = "zhaohaiyu"
	PASSWORD string = "zhy.1996"
	HOST string = "127.0.0.1"
	PORT string = "5672"
	VIRTUALHOST string = "/"
)

	//url := fmt.Sprintf()


func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func main() {
	conn, err := amqp.Dial(fmt.Sprintf("amqp://%s:%s@%s:%s%s", LOGIN, PASSWORD, HOST, PORT, VIRTUALHOST))
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	err = ch.ExchangeDeclare(
		"logs",   // name
		"fanout", // type
		true,     // durable
		false,    // auto-deleted
		false,    // internal
		false,    // no-wait
		nil,      // arguments
	)
	failOnError(err, "Failed to declare an exchange")

	body := bodyFrom(os.Args)
	err = ch.Publish(
		"logs", // exchange
		"",     // routing key
		false,  // mandatory
		false,  // immediate
		amqp.Publishing{
			ContentType: "text/plain",
			Body:        []byte(body),
		})
	failOnError(err, "Failed to publish a message")

	log.Printf(" [x] Sent %s", body)
}

func bodyFrom(args []string) string {
	var s string
	if (len(args) < 2) || os.Args[1] == "" {
		s = "hello"
	} else {
		s = strings.Join(args[1:], " ")
	}
	return s
}
```

不同的 Exchange 之间互不影响，相同 Exchange，相同队列的情况下，消息均等消费：

```go
package main

import (
	"fmt"
	"github.com/streadway/amqp"
	"log"
)

const (
	LOGIN string = "zhaohaiyu"
	PASSWORD string = "zhy.1996"
	HOST string = "127.0.0.1"
	PORT string = "5672"
	VIRTUALHOST string = "/"
)

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func main() {
	conn, err := amqp.Dial(fmt.Sprintf("amqp://%s:%s@%s:%s%s", LOGIN, PASSWORD, HOST, PORT, VIRTUALHOST))
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	err = ch.ExchangeDeclare(
		"logs",   // name
		"fanout", // type
		true,     // durable
		false,    // auto-deleted
		false,    // internal
		false,    // no-wait
		nil,      // arguments
	)
	failOnError(err, "Failed to declare an exchange")

	q, err := ch.QueueDeclare(
		"",    // name
		false, // durable
		false, // delete when unused
		true,  // exclusive
		false, // no-wait
		nil,   // arguments
	)
	failOnError(err, "Failed to declare a queue")

	err = ch.QueueBind(
		q.Name, // queue name
		"",     // routing key
		"logs", // exchange
		false,
		nil,
	)
	failOnError(err, "Failed to bind a queue")

	msgs, err := ch.Consume(
		q.Name, // queue
		"",     // consumer
		true,   // auto-ack
		false,  // exclusive
		false,  // no-local
		false,  // no-wait
		nil,    // args
	)
	failOnError(err, "Failed to register a consumer")

	forever := make(chan bool)

	go func() {
		for d := range msgs {
			log.Printf(" [x] %s", d.Body)
		}
	}()

	log.Printf(" [*] Waiting for logs. To exit press CTRL+C")
	<-forever
}
```

相同 Exchange，不同队列的情况下，一条消息可以被多个消费者获取。

## 路由 (routing) 模式

前面几种模式，消息的目标队列无法由生产者指定，而在路由模式下，消息的目标队列，可以由生产者指定，其示意图如下所示：

![](/images/2344773-20210831204942758-2093695080.png)

- 路由模式下`Exchange`的 type 为`direct`。
- 消息的目标队列可以由生产者按照`routingKey`规则指定。
- 消费者通过`BindingKey`绑定自己所关心的队列。
- 一条消息队可以被多个消息者获取。
- 只有`RoutingKey`与`BidingKey`相匹配的队列才会收到消息。

> `RoutingKey`用于生产者指定`Exchange`最终将消息路由到哪个队列，`BindingKey`用于消费者绑定到某个队列。

生产者：

```go
package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/streadway/amqp"
)

const (
	LOGIN string = "zhaohaiyu"
	PASSWORD string = "zhy.1996"
	HOST string = "127.0.0.1"
	PORT string = "5672"
	VIRTUALHOST string = "/"
)

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func main() {
	conn, err := amqp.Dial(fmt.Sprintf("amqp://%s:%s@%s:%s%s", LOGIN, PASSWORD, HOST, PORT, VIRTUALHOST))
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	err = ch.ExchangeDeclare(
		"logs_direct", // name
		"direct",      // type
		true,          // durable
		false,         // auto-deleted
		false,         // internal
		false,         // no-wait
		nil,           // arguments
	)
	failOnError(err, "Failed to declare an exchange")

	body := bodyFrom(os.Args)
	err = ch.Publish(
		"logs_direct",         // exchange
		severityFrom(os.Args), // routing key
		false, // mandatory
		false, // immediate
		amqp.Publishing{
			ContentType: "text/plain",
			Body:        []byte(body),
		})
	failOnError(err, "Failed to publish a message")

	log.Printf(" [x] Sent %s", body)
}

func bodyFrom(args []string) string {
	var s string
	if (len(args) < 3) || os.Args[2] == "" {
		s = "hello"
	} else {
		s = strings.Join(args[2:], " ")
	}
	return s
}

func severityFrom(args []string) string {
	var s string
	if (len(args) < 2) || os.Args[1] == "" {
		s = "info"
	} else {
		s = os.Args[1]
	}
	return s
}
```

消费者：

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/streadway/amqp"
)


const (
	LOGIN string = "zhaohaiyu"
	PASSWORD string = "zhy.1996"
	HOST string = "127.0.0.1"
	PORT string = "5672"
	VIRTUALHOST string = "/"
)

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func main() {
	conn, err := amqp.Dial(fmt.Sprintf("amqp://%s:%s@%s:%s%s", LOGIN, PASSWORD, HOST, PORT, VIRTUALHOST))
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	err = ch.ExchangeDeclare(
		"logs_direct", // name
		"direct",      // type
		true,          // durable
		false,         // auto-deleted
		false,         // internal
		false,         // no-wait
		nil,           // arguments
	)
	failOnError(err, "Failed to declare an exchange")

	q, err := ch.QueueDeclare(
		"",    // name
		false, // durable
		false, // delete when unused
		true,  // exclusive
		false, // no-wait
		nil,   // arguments
	)
	failOnError(err, "Failed to declare a queue")

	if len(os.Args) < 2 {
		log.Printf("Usage: %s [info] [warning] [error]", os.Args[0])
		os.Exit(0)
	}
	for _, s := range os.Args[1:] {
		log.Printf("Binding queue %s to exchange %s with routing key %s",
			q.Name, "logs_direct", s)
		err = ch.QueueBind(
			q.Name,        // queue name
			s,             // routing key
			"logs_direct", // exchange
			false,
			nil)
		failOnError(err, "Failed to bind a queue")
	}

	msgs, err := ch.Consume(
		q.Name, // queue
		"",     // consumer
		true,   // auto ack
		false,  // exclusive
		false,  // no local
		false,  // no wait
		nil,    // args
	)
	failOnError(err, "Failed to register a consumer")

	forever := make(chan bool)

	go func() {
		for d := range msgs {
			log.Printf(" [x] %s", d.Body)
		}
	}()

	log.Printf(" [*] Waiting for logs. To exit press CTRL+C")
	<-forever
}
```

## 主题 (Topic) 模式

主题模式是在路由模式的基础上，将路由键和某模式进行匹配。其中`#`表示匹配多个词，`*`表示匹配一个词，消费者可以通过某种模式的 BindKey 来达到订阅某个主题消息的目的，如示意图如下所示：

![](/images/2344773-20210831204958730-2111637898.png)

- 主题模式 Exchange 的 type 取值为 topic。
- 一条消息可以被多个消费者获取。

```go
package main

import (
	"fmt"
	"github.com/streadway/amqp"
	"log"
	"time"
)

const (
	LOGIN       string = "zhaohaiyu"
	PASSWORD    string = "zhy.1996"
	HOST        string = "127.0.0.1"
	PORT        string = "5672"
	VIRTUALHOST string = "/"
)

func publish() {
	url := fmt.Sprintf("amqp://%s:%s@%s:%s%s", LOGIN, PASSWORD, HOST, PORT, VIRTUALHOST)
	conn, err := amqp.Dial(url)
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	err = ch.ExchangeDeclare("testTopic", amqp.ExchangeTopic, true, false, false, false, nil)
	failOnError(err, "Failed to declare an exchange")

	for i := 0; i < 10; i++ {
		err = ch.Publish("testTopic", "yuemoxi", false, false, amqp.Publishing{
			ContentType: "text/plain",
			Body:        []byte(fmt.Sprintf("time:%v", time.Now())),
		})
		if err == nil {
			fmt.Println("发布成功!")
		}
		time.Sleep(time.Second)
	}
}

func get1() {
	url := fmt.Sprintf("amqp://%s:%s@%s:%s%s", LOGIN, PASSWORD, HOST, PORT, VIRTUALHOST)
	conn, err := amqp.Dial(url)
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	err = ch.ExchangeDeclare("testTopic", amqp.ExchangeTopic, true, false, false, false, nil)
	failOnError(err, "Failed to declare an exchange")

	q, err := ch.QueueDeclare("testTopic_get1", false, false, false, false, nil)
	failOnError(err, "Failed to declare a queue")

	err = ch.QueueBind(q.Name, "yuemox*", "testTopic", false, nil)
	failOnError(err, "Failed to bind a queue")

	msgs, err := ch.Consume(q.Name, "get1", true, false, false, false, nil)
	failOnError(err, "Failed to register a consumer")

	for msg := range msgs {
		log.Printf("get1: %s", msg.Body)
		time.Sleep(time.Millisecond * 500)
	}
}

func get2() {
	url := fmt.Sprintf("amqp://%s:%s@%s:%s%s", LOGIN, PASSWORD, HOST, PORT, VIRTUALHOST)
	conn, err := amqp.Dial(url)
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	err = ch.ExchangeDeclare("testTopic", amqp.ExchangeTopic, true, false, false, false, nil)
	failOnError(err, "Failed to declare an exchange")

	q, err := ch.QueueDeclare("testTopic_get2", false, false, false, false, nil)
	failOnError(err, "Failed to declare a queue")

	err = ch.QueueBind(q.Name, "#", "testTopic", false, nil)
	failOnError(err, "Failed to bind a queue")

	msgs, err := ch.Consume(q.Name, "get2", true, false, false, false, nil)
	failOnError(err, "Failed to register a consumer")

	for msg := range msgs {
		log.Printf("get2: %s", msg.Body)
		time.Sleep(time.Millisecond * 500)
	}

}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func main() {
	go publish()

	go get1()
	go get2()

	time.Sleep(time.Second * 20)
}

/*
结果：
发布成功!
2021/08/31 22:45:09 get1: time:2021-08-31 22:45:09.017664 +0800 CST m=+0.012626409
发布成功!
2021/08/31 22:45:10 get2: time:2021-08-31 22:45:10.022005 +0800 CST m=+1.016996649
2021/08/31 22:45:10 get1: time:2021-08-31 22:45:10.022005 +0800 CST m=+1.016996649
发布成功!
2021/08/31 22:45:11 get2: time:2021-08-31 22:45:11.023542 +0800 CST m=+2.018558384
2021/08/31 22:45:11 get1: time:2021-08-31 22:45:11.023542 +0800 CST m=+2.018558384
发布成功!
2021/08/31 22:45:12 get1: time:2021-08-31 22:45:12.028649 +0800 CST m=+3.023687209
2021/08/31 22:45:12 get2: time:2021-08-31 22:45:12.028649 +0800 CST m=+3.023687209
发布成功!
2021/08/31 22:45:13 get2: time:2021-08-31 22:45:13.033497 +0800 CST m=+4.028553608
2021/08/31 22:45:13 get1: time:2021-08-31 22:45:13.033497 +0800 CST m=+4.028553608
发布成功!
2021/08/31 22:45:14 get1: time:2021-08-31 22:45:14.03647 +0800 CST m=+5.031571881
2021/08/31 22:45:14 get2: time:2021-08-31 22:45:14.03647 +0800 CST m=+5.031571881
发布成功!
2021/08/31 22:45:15 get2: time:2021-08-31 22:45:15.036783 +0800 CST m=+6.031867631
2021/08/31 22:45:15 get1: time:2021-08-31 22:45:15.036783 +0800 CST m=+6.031867631
发布成功!
2021/08/31 22:45:16 get2: time:2021-08-31 22:45:16.041189 +0800 CST m=+7.036283180
2021/08/31 22:45:16 get1: time:2021-08-31 22:45:16.041189 +0800 CST m=+7.036283180
发布成功!
2021/08/31 22:45:17 get1: time:2021-08-31 22:45:17.043382 +0800 CST m=+8.038484117
2021/08/31 22:45:17 get2: time:2021-08-31 22:45:17.043382 +0800 CST m=+8.038484117
发布成功!
2021/08/31 22:45:18 get1: time:2021-08-31 22:45:18.04643 +0800 CST m=+9.041536815
2021/08/31 22:45:18 get2: time:2021-08-31 22:45:18.04643 +0800 CST m=+9.041536815
*/
```

## 延迟队列

### 什么是延迟队列

`延时队列`，首先，它是一种队列，队列意味着内部的元素是`有序`的，元素出队和入队是有方向性的，元素从一端进入，从另一端取出。

其次，`延时队列`，最重要的特性就体现在它的`延时`属性上，跟普通的队列不一样的是，`普通队列中的元素总是等着希望被早点取出处理，而延时队列中的元素则是希望被在指定时间得到取出和处理`，所以延时队列中的元素是都是带时间属性的，通常来说是需要被处理的消息或者任务。

简单来说，延时队列就是用来存放需要在指定时间被处理的元素的队列。

### 使用场景

1. 订单在十分钟之内未支付则自动取消。
2. 新创建的店铺，如果在十天内都没有上传过商品，则自动发送消息提醒。
3. 账单在一周内未支付，则自动结算。
4. 用户注册成功后，如果三天内没有登陆则进行短信提醒。
5. 用户发起退款，如果三天内没有得到处理则通知相关运营人员。
6. 预定会议后，需要在预定的时间点前十分钟通知各个与会人员参加会议。

### rabbitMQ中的TTL

在介绍延时队列之前，还需要先介绍一下RabbitMQ中的一个高级特性——`TTL（Time To Live）`。

`TTL`是什么呢？`TTL`是RabbitMQ中一个消息或者队列的属性，表明`一条消息或者该队列中的所有消息的最大存活时间`，单位是毫秒。换句话说，如果一条消息设置了TTL属性或者进入了设置TTL属性的队列，那么这条消息如果在TTL设置的时间内没有被消费，则会成为“死信”。如果同时配置了队列的TTL和消息的TTL，那么较小的那个值将会被使用。

### 如何利用rabbitMQ实现延迟队列

想想看，`延时队列`，不就是想要消息延迟多久被处理吗，TTL则刚好能让消息在延迟多久之后成为死信，另一方面，成为死信的消息都会被投递到死信队列里，这样只需要消费者一直消费死信队列里的消息就万事大吉了，因为里面的消息都是希望被立即处理的消息。

从下图可以大致看出消息的流向：

![](/images/2344773-20210901111932362-704286132.png)

生产者生产一条延时消息，根据需要延时时间的不同，利用不同的routingkey将消息路由到不同的延时队列，每个队列都设置了不同的TTL属性，并绑定在同一个死信交换机中，消息过期后，根据routingkey的不同，又会被路由到不同的死信队列中，消费者只需要监听对应的死信队列进行处理即可。

**go实现**

```go
package main

import (
	"fmt"
	"github.com/streadway/amqp"
	"log"
	"time"
)

const (
	LOGIN       string = "zhaohaiyu"
	PASSWORD    string = "zhy.1996"
	HOST        string = "127.0.0.1"
	PORT        string = "5672"
	VIRTUALHOST string = "/"
)

func publish() {
	url := fmt.Sprintf("amqp://%s:%s@%s:%s%s", LOGIN, PASSWORD, HOST, PORT, VIRTUALHOST)
	conn, err := amqp.Dial(url)
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	err = ch.ExchangeDeclare("testTopic", amqp.ExchangeTopic, true, false, false, false, nil)
	failOnError(err, "Failed to declare an exchange")

	for i := 0; i < 10; i++ {
		err = ch.Publish("testTopic", "yuemoxi", false, false, amqp.Publishing{
			ContentType: "text/plain",
			Body:        []byte(fmt.Sprintf("time:%v", time.Now())),
			Expiration:  "600000",
		})
		if err == nil {
			fmt.Println("发布成功!")
		}
		time.Sleep(time.Second)
	}
}

func get2() {
	url := fmt.Sprintf("amqp://%s:%s@%s:%s%s", LOGIN, PASSWORD, HOST, PORT, VIRTUALHOST)
	conn, err := amqp.Dial(url)
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	err = ch.ExchangeDeclare("testTopic", amqp.ExchangeTopic, true, false, false, false, nil)
	failOnError(err, "Failed to declare an exchange")

	q, err := ch.QueueDeclare("testTopic_get2", false, false, false, false, nil)
	failOnError(err, "Failed to declare a queue")

	//声明延时队列队列，该队列中消息如果过期，就将消息发送到交换器上，交换器就分发消息到普通队列
	q1, err := ch.QueueDeclare(
		"test_delay", //队列名
		true,         //持久化
		false,        //不用时是否自动删除
		true,
		false,
		amqp.Table{
			//当消息过期时把消息发送到logs这个交换器
			"x-dead-letter-exchange":    "ttlTopic",
			"x-dead-letter-routing-key": "ttlKey",
		},
	)

	failOnError(err, "Failed to bind a queue")
	
	err = ch.QueueBind(q.Name, "#", "testTopic", false, nil)
	failOnError(err, "Failed to bind a queue")

	err = ch.QueueBind(
		q1.Name,
		"ttlKey",
		"ttlTopic",
		false,
		nil,
	)
	
	msgs, err := ch.Consume(q.Name, "get2", true, false, false, false, nil)
	failOnError(err, "Failed to register a consumer")

	for msg := range msgs {
		log.Printf("get2: %s", msg.Body)
		time.Sleep(time.Millisecond * 500)
	}

}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func main() {
	go publish()

	go get2()

	time.Sleep(time.Second * 20)
}
```

## 参考文章

- https://juejin.cn/post/6916148736414466061
- [rabbitmq官网](https://www.rabbitmq.com/getstarted.html)
- https://www.cnblogs.com/mfrank/p/11260355.html
