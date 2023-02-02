---
title: "Go web源码解析"
date: 2021-03-13T17:35:23+08:00
draft: false
toc: true
categories: [go,network]
tags: [golang,http]
authors:
    - haiyux
---


## Go的web工作原理

在Go中使用及其简单的代码即可开启一个web服务。如下：

```go
//开启web服务
func test(){
    http.HandleFunc("/", sayHello)
    err := http.ListenAndServe(":9090",nil)
    if err!=nil {
        log.Fatal("ListenAndServer:",err)
    }
}

func sayHello(w http.ResponseWriter, r *http.Request){
    r.ParseForm()
    fmt.Println("path",r.URL.Path)
    fmt.Println("scheme",r.URL.Scheme)

    fmt.Fprintf(w, "Hello Guest!")
}
```

在使用`ListenAndServe`这个方法时，系统就会给我们指派一个路由器，`DefaultServeMux`是系统默认使用的路由器，如果`ListenAndServe`这个方法的第2个参数传入nil，系统就会默认使用`DefaultServeMux`。当然，这里也可以传入自定义的路由器。

先来看`http.HandleFunc("/", sayHello)`，从`HandleFunc`方法点进去，如下：

```go
func HandleFunc(pattern string, handler func(ResponseWriter, *Request)) {
    DefaultServeMux.HandleFunc(pattern, handler)
}
```

在这里调用了`DefaultServeMux`的`HandleFunc`方法，这个方法有两个参数，`pattern`是匹配的路由规则，`handler`表示这个路由规则对应的处理方法，并且这个处理方法有两个参数。

在我们书写的代码示例中，`pattern`对应`/`，`handler`对应`sayHello`，当我们在浏览器中输入`http://localhost:9090`时，就会触发`sayHello`方法。

我们再顺着`DefaultServeMux`的`HandleFunc`方法继续点下去，如下：

```go
func (mux *ServeMux) HandleFunc(pattern string, handler func(ResponseWriter, *Request)) {
    mux.Handle(pattern, HandlerFunc(handler))
}

```

在这个方法中，路由器又调用了`Handle`方法，注意这个`Handle`方法的第2个参数，将之前传入的`handler`这个响应方法强制转换成了`HandlerFunc`类型。

这个`HandlerFunc`类型到底是个什么呢？如下：

```go
type HandlerFunc func(ResponseWriter, *Request)

```

看来和我们定义的`SayHello`方法的类型都差不多。但是！！！
这个`HandlerFunc`默认实现了`ServeHTTP`接口！这样`HandlerFunc`对象就有了`ServeHTTP`方法！如下：

```go
// ServeHTTP calls f(w, r).
func (f HandlerFunc) ServeHTTP(w ResponseWriter, r *Request) {
    f(w, r)
}

```

这个细节是十分重要的，因为这一步关乎到当路由规则匹配时，相应的响应方法是否会被调用的问题！这个方法的调用时机会在下一小节中讲到。

接下来，我们返回去继续看`mux`的`Handle`方法，也就是这段代码`mux.Handle(pattern, HandlerFunc(handler))`。这段代码做了哪些事呢？源码如下：

```go
func (mux *ServeMux) Handle(pattern string, handler Handler) {
    mux.mu.Lock()
    defer mux.mu.Unlock()

    if pattern == "" {
        panic("http: invalid pattern " + pattern)
    }
    if handler == nil {
        panic("http: nil handler")
    }
    if mux.m[pattern].explicit {
        panic("http: multiple registrations for " + pattern)
    }

    if mux.m == nil {
        mux.m = make(map[string]muxEntry)
    }
    mux.m[pattern] = muxEntry{explicit: true, h: handler, pattern: pattern}

    if pattern[0] != '/' {
        mux.hosts = true
    }

    // Helpful behavior:
    // If pattern is /tree/, insert an implicit permanent redirect for /tree.
    // It can be overridden by an explicit registration.
    n := len(pattern)
    if n > 0 && pattern[n-1] == '/' && !mux.m[pattern[0:n-1]].explicit {
        // If pattern contains a host name, strip it and use remaining
        // path for redirect.
        path := pattern
        if pattern[0] != '/' {
            // In pattern, at least the last character is a '/', so
            // strings.Index can't be -1.
            path = pattern[strings.Index(pattern, "/"):]
        }
        url := &url.URL{Path: path}
        mux.m[pattern[0:n-1]] = muxEntry{h: RedirectHandler(url.String(), StatusMovedPermanently), pattern: pattern}
    }
}

```

代码挺多，其实主要就做了一件事，向`DefaultServeMux`的`map[string]muxEntry`中增加对应的路由规则和`handler`。

`map[string]muxEntry`是个什么鬼？

- `map`是一个字典对象，它保存的是`key-value`。
- `[string]`表示这个字典的`key`是`string`类型的，这个`key`值会保存我们的路由规则。
- `muxEntry`是一个实例对象，这个对象内保存了路由规则对应的处理方法。

找到相应代码，如下：

```go
//路由器
type ServeMux struct {
    mu    sync.RWMutex
    m     map[string]muxEntry //路由规则，一个string对应一个mux实例对象，map的key就是注册的路由表达式(string类型的)
    hosts bool // whether any patterns contain hostnames
}

//muxEntry
type muxEntry struct {
    explicit bool
    h        Handler //这个路由表达式对应哪个handler
    pattern  string
}

//路由响应方法
type Handler interface {
    ServeHTTP(ResponseWriter, *Request)  //handler的路由实现器
}

```

`ServeMux`就是这个系统默认的路由器。

最后，总结一下这个部分：

1. 调用`http.HandleFunc("/", sayHello)`
2. 调用`DefaultServeMux`的`HandleFunc()`，把我们定义的`sayHello()`包装成`HandlerFunc`类型
3. 继续调用`DefaultServeMux`的`Handle()`，向`DefaultServeMux`的`map[string]muxEntry`中增加路由规则和对应的`handler`

OK，这部分代码做的事就这么多，第一部分结束。

第二部分主要就是研究这句代码`err := http.ListenAndServe(":9090",nil)`，也就是`ListenAndServe`这个方法。从这个方法点进去，如下：

```go
func ListenAndServe(addr string, handler Handler) error {
    server := &Server{Addr: addr, Handler: handler}
    return server.ListenAndServe()
}

```

在这个方法中，初始化了一个`server`对象，然后调用这个`server`对象的`ListenAndServe`方法，在这个方法中，如下：

```go
func (srv *Server) ListenAndServe() error {
    addr := srv.Addr
    if addr == "" {
        addr = ":http"
    }
    ln, err := net.Listen("tcp", addr)
    if err != nil {
        return err
    }
    return srv.Serve(tcpKeepAliveListener{ln.(*net.TCPListener)})
}

```

在这个方法中，调用了`net.Listen("tcp", addr)`，也就是底层用TCP协议搭建了一个服务，然后监控我们设置的端口。

代码的最后，调用了`srv`的`Serve`方法，如下：

```go
func (srv *Server) Serve(l net.Listener) error {
    defer l.Close()
    if fn := testHookServerServe; fn != nil {
        fn(srv, l)
    }
    var tempDelay time.Duration // how long to sleep on accept failure

    if err := srv.setupHTTP2_Serve(); err != nil {
        return err
    }

    srv.trackListener(l, true)
    defer srv.trackListener(l, false)

    baseCtx := context.Background() // base is always background, per Issue 16220
    ctx := context.WithValue(baseCtx, ServerContextKey, srv)
    ctx = context.WithValue(ctx, LocalAddrContextKey, l.Addr())
    for {
        rw, e := l.Accept()
        if e != nil {
            select {
            case <-srv.getDoneChan():
                return ErrServerClosed
            default:
            }
            if ne, ok := e.(net.Error); ok && ne.Temporary() {
                if tempDelay == 0 {
                    tempDelay = 5 * time.Millisecond
                } else {
                    tempDelay *= 2
                }
                if max := 1 * time.Second; tempDelay > max {
                    tempDelay = max
                }
                srv.logf("http: Accept error: %v; retrying in %v", e, tempDelay)
                time.Sleep(tempDelay)
                continue
            }
            return e
        }
        tempDelay = 0
        c := srv.newConn(rw)
        c.setState(c.rwc, StateNew) // before Serve can return
        go c.serve(ctx)
    }
}

```

最后3段代码比较重要，也是Go语言支持高并发的体现，如下：

```go
c := srv.newConn(rw)
c.setState(c.rwc, StateNew) // before Serve can return
go c.serve(ctx)

```

上面那一大坨代码，总体意思是进入方法后，首先开了一个`for`循环，在`for`循环内时刻Accept请求，请求来了之后，会为每个请求创建一个`Conn`，然后单独开启一个`goroutine`，把这个请求的数据当做参数扔给这个`Conn`去服务：`go c.serve()`。用户的每一次请求都是在一个新的`goroutine`去服务，每个请求间相互不影响。

在`conn`的`serve`方法中，有一句代码很重要，如下：

```go
serverHandler{c.server}.ServeHTTP(w, w.req)

```

表示`serverHandler`也实现了`ServeHTTP`接口，`ServeHTTP`方法实现如下：

```go
func (sh serverHandler) ServeHTTP(rw ResponseWriter, req *Request) {
    handler := sh.srv.Handler
    if handler == nil {
        handler = DefaultServeMux
    }
    if req.RequestURI == "*" && req.Method == "OPTIONS" {
        handler = globalOptionsHandler{}
    }
    handler.ServeHTTP(rw, req)
}

```

在这里如果`handler`为空（这个`handler`就可以理解为是我们自定义的路由器），就会使用系统默认的`DefaultServeMux`，代码的最后调用了`DefaultServeMux`的`ServeHTTP()`

```go
func (mux *ServeMux) ServeHTTP(w ResponseWriter, r *Request) {
    if r.RequestURI == "*" {
        if r.ProtoAtLeast(1, 1) {
            w.Header().Set("Connection", "close")
        }
        w.WriteHeader(StatusBadRequest)
        return
    }
    h, _ := mux.Handler(r)  //这里返回的h是Handler接口对象
    h.ServeHTTP(w, r)       //调用Handler接口对象的ServeHTTP方法实际上就调用了我们定义的sayHello方法
}

```

路由器接收到请求之后，如果是`*`那么关闭链接，如果不是`*`就调用`mux.Handler(r)`返回该路由对应的处理`Handler`，然后执行该`handler`的`ServeHTTP`方法，也就是这句代码`h.ServeHTTP(w, r)`，`mux.Handler(r)`做了什么呢？如下：

```go
func (mux *ServeMux) Handler(r *Request) (h Handler, pattern string) {
    if r.Method != "CONNECT" {
        if p := cleanPath(r.URL.Path); p != r.URL.Path {
            _, pattern = mux.handler(r.Host, p)
            url := *r.URL
            url.Path = p
            return RedirectHandler(url.String(), StatusMovedPermanently), pattern
        }
    }

    return mux.handler(r.Host, r.URL.Path)
}

func (mux *ServeMux) handler(host, path string) (h Handler, pattern string) {
    mux.mu.RLock()
    defer mux.mu.RUnlock()

    // Host-specific pattern takes precedence over generic ones
    if mux.hosts {
        h, pattern = mux.match(host + path)
    }
    if h == nil {
        h, pattern = mux.match(path)
    }
    if h == nil {
        h, pattern = NotFoundHandler(), ""
    }
    return
}

func (mux *ServeMux) match(path string) (h Handler, pattern string) {
    var n = 0
    for k, v := range mux.m {  //mux.m就是系统默认路由的map
        if !pathMatch(k, path) {
            continue
        }
        if h == nil || len(k) > n {
            n = len(k)
            h = v.h
            pattern = v.pattern
        }
    }
    return
}

```

它会根据用户请求的`URL`到路由器里面存储的`map`中匹配，匹配成功就会返回存储的`handler`，调用这个`handler`的`ServeHTTP()`就可以执行到相应的处理方法了，这个处理方法实际上就是我们刚开始定义的`sayHello()`，只不过这个`sayHello()`被`HandlerFunc`又包了一层，因为`HandlerFunc`实现了`ServeHTTP`接口，所以在调用`HandlerFunc`对象的`ServeHTTP()`时，实际上在`ServeHTTP ()`的内部调用了我们的`sayHello()`。

总结一下：
1. 调用`http.ListenAndServe(":9090",nil)`
2. 实例化`server`
3. 调用`server`的`ListenAndServe()`
4. 调用`server`的`Serve`方法，开启`for`循环，在循环中Accept请求
5. 对每一个请求实例化一个`Conn`，并且开启一个`goroutine`为这个请求进行服务`go c.serve()`
6. 读取每个请求的内容`c.readRequest()`
7. 调用`serverHandler`的`ServeHTTP()`，如果`handler`为空，就把`handler`设置为系统默认的路由器`DefaultServeMux`
8. 调用`handler`的`ServeHTTP()` =>实际上是调用了`DefaultServeMux`的`ServeHTTP()`
9. 在`ServeHTTP()`中会调用路由对应处理`handler`
10. 在路由对应处理`handler`中会执行`sayHello()`

有一个需要注意的点：
`DefaultServeMux`和路由对应的处理方法`handler`都实现了`ServeHTTP`接口，他们俩都有`ServeHTTP`方法，但是方法要达到的目的不同，在`DefaultServeMux`的`ServeHttp()`里会执行路由对应的处理`handler`的`ServeHttp()`。

## 文章转自

https://juejin.cn/post/6844903550993039374