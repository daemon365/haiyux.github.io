---
title: "Go context包"
date: 2020-10-24T12:26:32+08:00
draft: false
toc: true
categories: [go]
tags: [golang]
authors:
    - haiyux
---

## go context标准库

context包在Go1.7版本时加入到标准库中。其设计目标是给Golang提供一个标准接口来给其他任务发送取消信号和传递数据。其具体作用为：

*   可以通过context发送取消信号。

*   可以指定截止时间（Deadline)，context在截止时间到期后自动发送取消信号。

*   可以通过context传输一些数据。

**context在Golang中最主要的用途是控制协程任务的取消**，但是context除了协程以外也可以用在线程控制等非协程的情况。


## 基本概念

context的核心是其定义的Context接口类型。围绕着Context接口类型存在两种角色：

*   父任务：创建Context，将Context对象传递给子任务，并且根据需要发送取消信号来结束子任务。

*   子任务：使用Context类型对象，当收到父任务发来的取消信号，结束当前任务并退出。

接下来我们从这两个角色的视角分别看一下Context对象。

## context接口

```golang l
type Context interface {  Deadline() (deadline time.Time, ok bool)  Done() chan struct{}  Err() error  Value(key interface{}) interface{} }
```

*   Deadline方法需要返回当前Context被取消的时间，也就是完成工作的截止时间（deadline）；

*   Done方法需要返回一个Channel，这个Channel会在当前工作完成或者上下文被取消之后关闭，多次调用Done方***返回同一个Channel；

*   Err方***返回当前Context结束的原因，它只会在Done返回的Channel被关闭时才会返回非空的值；

    *   如果当前Context被取消就会返回Canceled错误；

    *   如果当前Context超时就会返回DeadlineExceeded错误；

*   Value方***从Context中返回键对应的值，对于同一个上下文来说，多次调用Value 并传入相同的Key会返回相同的结果，该方法仅用于传递跨API和进程间跟请求域的数据；

## Background()和TODO()

Go内置两个函数：Background()和TODO()，这两个函数分别返回一个实现了Context接口的background和todo。我们代码中最开始都是以这两个内置的上下文对象作为最顶层的partent context，衍生出更多的子上下文对象。

*   Background()主要用于main函数、初始化以及测试代码中，作为Context这个树结构的最顶层的Context，也就是根Context。

*   TODO()，它目前还不知道具体的使用场景，如果我们不知道该使用什么Context的时候，可以使用这个。

*   background和todo本质上都是emptyCtx结构体类型，是一个不可取消，没有设置截止时间，没有携带任何值的Context。

## With函数

*   WithCancel函数，传递一个父Context作为参数，返回子Context，以及一个取消函数用来取消Context

*   WithDeadline函数，和WithCancel差不多，它会多传递一个截止时间参数，意味着到了这个时间点，会自动取消Context，当然我们也可以不等到这个时候，可以提前通过取消函数进行取消

*   WithTimeout和WithDeadline基本上一样，这个表示是超时自动取消，是多少时间后自动取消Context的意思

*   WithValue函数和取消Context无关，它是为了生成一个绑定了一个键值对数据的Context，这个绑定的数据可以通过Context.Value方法访问到

## Context使用原则

*   不要把Context放在结构体中，要以参数的方式进行传递

*   以Context作为参数的函数方法，应该把Context作为第一个参数，放在第一位]

*   给一个函数方法传递Context的时候，不要传递nil，如果不知道传递什么，就使用context.TODO

*   Context的Value相关方法应该传递必须的数据，不要什么数据都使用这个传递

```go
package main  
import (  
    "context"  
    "fmt"  
    "time" 
)   

func main() {  
    server1()  
    time.Sleep(time.Second) 
}   

func server1() {  
		ctx, cancel := context.WithTimeout(context.Background(),time.Millisecond * 30 )// 30毫秒后过期  
		defer cancel()  
		ctx = context.WithValue(ctx, "name", "zhaohaiyu")  
		for i:=0;i<100;i++{   
      time.Sleep(time.Millisecond * 10)   
      go server2(ctx)  
		}  
}  
func server2(ctx context.Context) {  
		select {  
				case ctx.Done():   
						fmt.Println("打断执行")   
				return  default:   
						name,ok := ctx.Value("name").(string)   
						if !ok{    
								fmt.Println("没有取到")    
								return   
						}   
				fmt.Println("name=",name)  
				} 
}
```

## 请求作用域上下文

在 Go 服务中，每个传入的请求都在其自己的goroutine 中处理。请求处理程序通常启动额外的 goroutine 来访问其他后端，如数据库和 RPC服务。处理请求的 goroutine 通常需要访问特定于请求(request-specific context)的值，例如最终用户的身份、授权令牌和请求的截止日期(deadline)。当一个请求被取消或超时时，处理该请求的所有 goroutine 都应该快速退出(fail fast)，这样系统就可以回收它们正在使用的任何资源。
Go 1.7 引入一个 context 包，它使得跨 API 边界的请求范围元数据、取消信号和截止日期很容易传递给处理请求所涉及的所有 goroutine(显示传递)。

**其他语言: Thread Local Storage(TLS)，XXXContext**

```go
type Context interface {
	// Deadline returns the time when work done on behalf of this context
	// should be canceled. Deadline returns ok==false when no deadline is
	// set. Successive calls to Deadline return the same results.
	Deadline() (deadline time.Time, ok bool)

	// Done returns a channel that's closed when work done on behalf of this
	// context should be canceled. Done may return nil if this context can
	// never be canceled. Successive calls to Done return the same value.
	// The close of the Done channel may happen asynchronously,
	// after the cancel function returns.
	//
	// WithCancel arranges for Done to be closed when cancel is called;
	// WithDeadline arranges for Done to be closed when the deadline
	// expires; WithTimeout arranges for Done to be closed when the timeout
	// elapses.
	//
	// Done is provided for use in select statements:
	//
	//  // Stream generates values with DoSomething and sends them to out
	//  // until DoSomething returns an error or ctx.Done is closed.
	//  func Stream(ctx context.Context, out chan<- Value) error {
	//  	for {
	//  		v, err := DoSomething(ctx)
	//  		if err != nil {
	//  			return err
	//  		}
	//  		select {
	//  		case <-ctx.Done():
	//  			return ctx.Err()
	//  		case out <- v:
	//  		}
	//  	}
	//  }
	//
	// See https://blog.golang.org/pipelines for more examples of how to use
	// a Done channel for cancellation.
	Done() <-chan struct{}

	// If Done is not yet closed, Err returns nil.
	// If Done is closed, Err returns a non-nil error explaining why:
	// Canceled if the context was canceled
	// or DeadlineExceeded if the context's deadline passed.
	// After Err returns a non-nil error, successive calls to Err return the same error.
	Err() error

	// Value returns the value associated with this context for key, or nil
	// if no value is associated with key. Successive calls to Value with
	// the same key returns the same result.
	//
	// Use context values only for request-scoped data that transits
	// processes and API boundaries, not for passing optional parameters to
	// functions.
	//
	// A key identifies a specific value in a Context. Functions that wish
	// to store values in Context typically allocate a key in a global
	// variable then use that key as the argument to context.WithValue and
	// Context.Value. A key can be any type that supports equality;
	// packages should define keys as an unexported type to avoid
	// collisions.
	//
	// Packages that define a Context key should provide type-safe accessors
	// for the values stored using that key:
	//
	// 	// Package user defines a User type that's stored in Contexts.
	// 	package user
	//
	// 	import "context"
	//
	// 	// User is the type of value stored in the Contexts.
	// 	type User struct {...}
	//
	// 	// key is an unexported type for keys defined in this package.
	// 	// This prevents collisions with keys defined in other packages.
	// 	type key int
	//
	// 	// userKey is the key for user.User values in Contexts. It is
	// 	// unexported; clients use user.NewContext and user.FromContext
	// 	// instead of using this key directly.
	// 	var userKey key
	//
	// 	// NewContext returns a new Context that carries value u.
	// 	func NewContext(ctx context.Context, u *User) context.Context {
	// 		return context.WithValue(ctx, userKey, u)
	// 	}
	//
	// 	// FromContext returns the User value stored in ctx, if any.
	// 	func FromContext(ctx context.Context) (*User, bool) {
	// 		u, ok := ctx.Value(userKey).(*User)
	// 		return u, ok
	// 	}
	Value(key interface{}) interface{}
}

 func IsAdminUser(ctx context.Context) {
         x := token.GetToken(ctx)
         userObject := auth.AuthenticateToken(x)
         return userObject.IsAdmin || userObject.IsRoot()
 }
```

如何将 context 集成到 API 中？
在将 context 集成到 API 中时，要记住的最重要的一点是，它的作用域是请求级别	的。例如，沿单个数据库查询存在是有意义的，但沿数据库对象存在则没有意义。
目前有两种方法可以将 context 对象集成到 API 中：

- The first parameter of a function call 

  	首参数传递 context 对象，比如，参考  net 包 Dialer.DialContext。此函数执行正常的 Dial 操作，但可以通过 context 对象取消函数调用。

  `func (d *Dialer) DialContext(ctx context.Context,network,address string) (Conn,error)`

- Optional config on a request structure
      在第一个 request 对象中携带一个可选的 context 对象。例如 net/http 库的 Request.WithContext，通过携带给定的 context 对象，返回一个新的 Request 对象。 

   `func (r *Request) WithContext(ctx context.Context) *Request`

![](/images/2344773-20210819165156921-1630633742.png)

### 不要在stuct类型中存储上下文

不要在结构题类型中存储上下文；相反，应该显式地将上下文传递给每个需要它的函数。上下文应该是第一个参数，通常命名为ctx:

```go
  func DoSomething(ctx context.Context,arg Arg) error {
          // .. use ctx
  }
```

对服务器的传入请求应创建上下文。
使用 context 的一个很好的心智模型是它应该在程序中流动，应该贯穿你的代码。这通常意味着您不希望将其存储在结构体之中。它从一个函数传递到另一个函数，并根据需要进行扩展。理想情况下，每个请求都会创建一个 context 对象，并在请求结束时过期。
不存储上下文的一个例外是，当您需要将它放入一个结构中时，该结构纯粹用作通过通道传递的消息。如下例所示。

```go
type message struct {
        responseChan chan<- int
        parameter string
        ctx context.Context
}
```

## context.WithValue

比如我们新建了一个基于 context.Background() 的 ctx1，携带了一个 map 的数据，map 中包含了 “k1”: “v1” 的一个键值对，ctx1 被两个 goroutine 同时使用作为函数签名传入，如果我们修改了 这个map，会导致另外进行读 context.Value 的 goroutine 和修改 map 的 goroutine，在 map 对象上产生 data race。因此我们要使用 copy-on-write 的思路，解决跨多个 goroutine 使用数据、修改数据的场景。

![](/images/2344773-20210819165219664-351851684.png)

context.WithValue 内部基于 valueCtx 实现:

```go
type valueCtx struct {
        Context
        key,val interface{}
}
```

为了实现不断的 WithValue，构建新的 context，内部在查找 key 时候，使用递归方式不断从当前，从父节点寻找匹配的 key，直到 root context(Backgrond 和 TODO Value 函数会返回 nil)。

```go
func (c *valueCtx) Value(key interface{}( interface{} {
        if c.key == key {
                return c.val
        }
        return c.Context.Value(key)
}
```

![](/images/2344773-20210819165231515-1238192665.png)

## 调试或跟踪数据在上下文中传递是安全的

context.WithValue 方法允许上下文携带请求范围的数据。这些数据必须是安全的，以便多个 goroutine 同时使用。这里的数据，更多是面向请求的元数据，不应该作为函数的可选参数来使用(比如 context 里面挂了一个sql.Tx 对象，传递到 Dao 层使用)，因为元数据相对函数参数更加是隐含的，面向请求的。而参数是更加显示的。

- 同一个 context 对象可以传递给在不同 goroutine 中运行的函数；上下文对于多个 goroutine 同时使用是安全的。对于值类型最容易犯错的地方，在于 context value 应该是 immutable 的，每次重新赋值应该是新的 context，即: context.WithValue(ctx, oldvalue)

https://pkg.go.dev/google.golang.org/grpc/metadata
Context.Value should inform, not control

```go
func WithValue(parent Context,key val interface{}) Context {
	if parent == nil {
		panic("connot creat context from nil parent")
	}
	if key == nil {
		panic("nil key")
	}
	if !reflectlite.Typeof(key).Comparable() {
		panic("key is not comparable")
	}
	return &valueCtx{parent,key,val}
}

type valueCtx struct {
	Context
	key,val interface{}
}
```

用于传递作用域的参数的可选api和用于传递作用域的参数的可选api。比如 染色，API 重要性，Trace

比如我们新建了一个基于 context.Background() 的 ctx1，携带了一个 map 的数据，map 中包含了 “k1”: “v1” 的一个键值对，ctx1 被两个 goroutine 同时使用作为函数签名传入，如果我们修改了 这个map，会导致另外进行读 context.Value 的 goroutine 和修改 map 的 goroutine，在 map 对象上产生 data race。因此我们要使用 copy-on-write 的思路，解决跨多个 goroutine 使用数据、修改数据的场景。

![](/images/2344773-20210819165256515-1747864330.png)

COW: 从 ctx1 中获取 map1(可以理解为 v1 版本的 map 数据)。构建一个新的 map 对象 map2，复制所有 map1 数据，同时追加新的数据 “k2”: “v2” 键值对，使用 context.WithValue 创建新的 ctx2，ctx2 会传递到其他的 goroutine 中。这样各自读取的副本都是自己的数据，写行为追加的数据，在 ctx2 中也能完整读取到，同时也不会污染 ctx1 中的数据。

![](/images/2344773-20210819165312384-60868291.png)

**当上下文被取消时，从它派生的所有上下文也被取消**

当一个 context 被取消时，从它派生的所有 context 也将被取消。WithCancel(ctx) 参数 ctx 认为是 parent ctx，在内部会进行一个传播关系链的关联。Done() 返回 一个 chan，当我们取消某个parent context, 实际上上会递归层层 cancel 掉自己的 child context 的 done chan 从而让整个调用链中所有监听 cancel 的 goroutine退出。

![](/images/2344773-20210819165327597-1159333262.png)

```go
package main

import (
	"context"
	"fmt"
)

func main() {
	gen := func(ctx context.Context) <-chan int {
		dst := make(chan int)
		n := 1
		go func(){
			for {
				select {
				case <- ctx.Done():
					return
				case dst <- n:
					n++
				}
			}
		}()
	}
	return dst

	ctx,cancel := context.WithCancel(context.Backgroup())

	for n := range gen(ctx) {
		fmt.Println(n)
		if n == 5 {
			break
		}
	}
```

**所有阻塞/长操作都应可取消**

如果要实现一个超时控制，通过上面的context 的parent/child 机制，其实我们只需要启动一个定时器，然后在超时的时候，直接将当前的 context 给 cancel 掉，就可以实现监听在当前和下层的额context.Done() 的 goroutine 的退出。

![](/images/2344773-20210819165341680-872807308.png)

```go
package main

import (
	"context"
	"fmt"
	"fmt"
)


const shortDuration = time.Millisecond

func main() {
	d := time.Now().Add(shortDuration)
	ctx,cancel := context.WithDeadline(context.Backgroup(),d)

	defer canel()

	select {
	case <-time.After(time.Second):
		fmt.Println("overslept")
	case <- ctx.Done():
		fmt.Println(ctx.Err())
	}
}
```
