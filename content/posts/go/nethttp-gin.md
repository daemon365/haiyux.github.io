---
title: "Nethttp Gin"
date: 2021-12-16T22:09:38+08:00
draft: false
toc: true
categories: [go]
tags: [golang,http]
authors:
    - haiyux
featuredImagePreview: /img/go.webp
---

## net/http 路由注册

```go
func test1() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "Hello world!")
    })
    err := http.ListenAndServe(":9001", nil)
    if err != nil {
        log.Fatal("ListenAndServer:", err)
    }
}
```

在使用`ListenAndServe`这个方法时，系统就会给我们指派一个路由器，`DefaultServeMux`是系统默认使用的路由器，如果`ListenAndServe`这个方法的第2个参数传入nil，系统就会默认使用`DefaultServeMux`。当然，这里也可以传入自定义的路由器。

先看`http.HandleFunc("/", ...)`，从`HandleFunc`方法点进去，如下：

```go
func HandleFunc(pattern string, handler func(ResponseWriter, *Request)) {
    DefaultServeMux.HandleFunc(pattern, handler)
}
```

在这里调用了`DefaultServeMux`的`HandleFunc`方法，这个方法有两个参数，`pattern`是匹配的路由规则，`handler`表示这个路由规则对应的处理方法，并且这个处理方法有两个参数。

在我们书写的代码示例中，`pattern`对应`/`，`handler`对应`sayHello`，当我们在浏览器中输入`http://localhost:9001`时，就会触发匿名函数。

我们再顺着`DefaultServeMux`的`HandleFunc`方法继续点下去，如下：

```go
func (mux *ServeMux) HandleFunc(pattern string, handler func(ResponseWriter, *Request)) {
    if handler == nil {
        panic("http: nil handler")
    }
    mux.Handle(pattern, HandlerFunc(handler))
}
```

在这个方法中，路由器又调用了`Handle`方法，注意这个`Handle`方法的第2个参数，将之前传入的`handler`这个响应方法强制转换成了`HandlerFunc`类型。

这个`HandlerFunc`类型到底是个什么呢？如下：

```go
type HandlerFunc func(ResponseWriter, *Request)
```

看来和我们定义的"/"的匿名函数的类型都差不多。但是！！！ 这个`HandlerFunc`默认实现了`ServeHTTP`接口！这样`HandlerFunc`对象就有了`ServeHTTP`方法！如下：

```go
// ServeHTTP calls f(w, r).
func (f HandlerFunc) ServeHTTP(w ResponseWriter, r *Request) {
    f(w, r)
}
```

接下来，我们返回去继续看`mux`的`Handle`方法，也就是这段代码`mux.Handle(pattern, HandlerFunc(handler))`。这段代码做了哪些事呢？源码如下

```go
// Handle registers the handler for the given pattern.
// If a handler already exists for pattern, Handle panics.
func (mux *ServeMux) Handle(pattern string, handler Handler) {
    mux.mu.Lock()
    defer mux.mu.Unlock()

    if pattern == "" {
        panic("http: invalid pattern")
    }
    if handler == nil {
        panic("http: nil handler")
    }
    if _, exist := mux.m[pattern]; exist {
        panic("http: multiple registrations for " + pattern)
    }

    if mux.m == nil {
        mux.m = make(map[string]muxEntry)
    }
    e := muxEntry{h: handler, pattern: pattern}
    mux.m[pattern] = e
    if pattern[len(pattern)-1] == '/' {
        mux.es = appendSorted(mux.es, e)
    }

    if pattern[0] != '/' {
        mux.hosts = true
    }
}
```

主要就做了一件事，向`DefaultServeMux`的`map[string]muxEntry`中增加对应的路由规则和`handler`。

`map[string]muxEntry`是个什么鬼？

- `map`是一个字典对象，它保存的是`key-value`。

- `[string]`表示这个字典的`key`是`string`类型的，这个`key`值会保存我们的路由规则。

- `muxEntry`是一个实例对象，这个对象内保存了路由规则对应的处理方法。

- `mux.es` 为模糊匹配 有长倒短排序 比如有路由`/hello/` 访问`/hello/world` 时没有路由 会落到`/hello/`上

找到相应代码，如下：

```go
// 路由器
type ServeMux struct {
    mu    sync.RWMutex
    m     map[string]muxEntry
    es    []muxEntry // slice of entries sorted from longest to shortest.
    hosts bool       // whether any patterns contain hostnames
}

type muxEntry struct {
    h       Handler
    pattern string
}

// 路由响应方法
type Handler interface {
    ServeHTTP(ResponseWriter, *Request)
}
```

## net/http 运行

第二部分主要就是研究这句代码`err := http.ListenAndServe(":9001",nil)`，也就是`ListenAndServe`这个方法。从这个方法点进去，如下：

```go
func ListenAndServe(addr string, handler Handler) error {
    server := &Server{Addr: addr, Handler: handler}
    return server.ListenAndServe()
}
```

在这个方法中，初始化了一个`server`对象，然后调用这个`server`对象的`ListenAndServe`方法，在这个方法中，如下：

```go
func (srv *Server) ListenAndServe() error {
    if srv.shuttingDown() {
        return ErrServerClosed
    }
    addr := srv.Addr
    if addr == "" {
        addr = ":http"
    }
    ln, err := net.Listen("tcp", addr)
    if err != nil {
        return err
    }
    return srv.Serve(ln)
}
```

在这个方法中，调用了`net.Listen("tcp", addr)`，也就是底层用TCP协议搭建了一个服务，然后监控我们设置的端口。

代码的最后，调用了`srv`的`Serve`方法，如下：

```go
func (srv *Server) Serve(l net.Listener) error {
    if fn := testHookServerServe; fn != nil {
        fn(srv, l) // call hook with unwrapped listener
    }

    origListener := l
    l = &onceCloseListener{Listener: l}
    defer l.Close()

    if err := srv.setupHTTP2_Serve(); err != nil {
        return err
    }

    if !srv.trackListener(&l, true) {
        return ErrServerClosed
    }
    defer srv.trackListener(&l, false)

    baseCtx := context.Background()
    if srv.BaseContext != nil {
        baseCtx = srv.BaseContext(origListener)
        if baseCtx == nil {
            panic("BaseContext returned a nil context")
        }
    }

    var tempDelay time.Duration // how long to sleep on accept failure

    ctx := context.WithValue(baseCtx, ServerContextKey, srv)
    for {
        rw, err := l.Accept()
        if err != nil {
            select {
            case <-srv.getDoneChan():
                return ErrServerClosed
            default:
            }
            if ne, ok := err.(net.Error); ok && ne.Temporary() {
                if tempDelay == 0 {
                    tempDelay = 5 * time.Millisecond
                } else {
                    tempDelay *= 2
                }
                if max := 1 * time.Second; tempDelay > max {
                    tempDelay = max
                }
                srv.logf("http: Accept error: %v; retrying in %v", err, tempDelay)
                time.Sleep(tempDelay)
                continue
            }
            return err
        }
        connCtx := ctx
        if cc := srv.ConnContext; cc != nil {
            connCtx = cc(connCtx, rw)
            if connCtx == nil {
                panic("ConnContext returned nil")
            }
        }
        tempDelay = 0
        c := srv.newConn(rw)
        c.setState(c.rwc, StateNew, runHooks) // before Serve can return
        go c.serve(connCtx)
    }
}
```

最后3段代码比较重要，也是Go语言支持高并发的体现，如下：

```go
c := srv.newConn(rw)
c.setState(c.rwc, StateNew, runHooks) // before Serve can return
go c.serve(connCtx)
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

    if req.URL != nil && strings.Contains(req.URL.RawQuery, ";") {
        var allowQuerySemicolonsInUse int32
        req = req.WithContext(context.WithValue(req.Context(), silenceSemWarnContextKey, func() {
            atomic.StoreInt32(&allowQuerySemicolonsInUse, 1)
        }))
        defer func() {
            if atomic.LoadInt32(&allowQuerySemicolonsInUse) == 0 {
                sh.srv.logf("http: URL query contains semicolon, which is no longer a supported separator; parts of the query may be stripped when parsed; see golang.org/issue/25192")
            }
        }()
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
    h.ServeHTTP(w, r)  //调用Handler接口对象的ServeHTTP方法实际上就调用了我们定义的sayHello方法
}
```

```go
func (mux *ServeMux) Handler(r *Request) (h Handler, pattern string) {

    // CONNECT requests are not canonicalized.
    if r.Method == "CONNECT" {
        // If r.URL.Path is /tree and its handler is not registered,
        // the /tree -> /tree/ redirect applies to CONNECT requests
        // but the path canonicalization does not.
        if u, ok := mux.redirectToPathSlash(r.URL.Host, r.URL.Path, r.URL); ok {
            return RedirectHandler(u.String(), StatusMovedPermanently), u.Path
        }

        return mux.handler(r.Host, r.URL.Path)
    }

    // All other requests have any port stripped and path cleaned
    // before passing to mux.handler.
    host := stripHostPort(r.Host)
    path := cleanPath(r.URL.Path)

    // If the given path is /tree and its handler is not registered,
    // redirect for /tree/.
    if u, ok := mux.redirectToPathSlash(host, path, r.URL); ok {
        return RedirectHandler(u.String(), StatusMovedPermanently), u.Path
    }

    if path != r.URL.Path {
        _, pattern = mux.handler(host, path)
        u := &url.URL{Path: path, RawQuery: r.URL.RawQuery}
        return RedirectHandler(u.String(), StatusMovedPermanently), pattern
    }

    return mux.handler(host, r.URL.Path)
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
    // Check for exact match first.
    v, ok := mux.m[path]
    if ok {
        return v.h, v.pattern
    }

    // Check for longest valid match.  mux.es contains all patterns
    // that end in / sorted from longest to shortest.
    for _, e := range mux.es {
        if strings.HasPrefix(path, e.pattern) {
            return e.h, e.pattern
        }
    }
    return nil, ""
}
```

它会根据用户请求的`URL`到路由器里面存储的`map`中匹配，匹配成功就会返回存储的`handler`，调用这个`handler`的`ServeHTTP()`就可以执行到相应的处理方法了，这个处理方法实际上就是我们刚开始定义的`sayHello()`，只不过这个`sayHello()`被`HandlerFunc`又包了一层，因为`HandlerFunc`实现了`ServeHTTP`接口，所以在调用`HandlerFunc`对象的`ServeHTTP()`时，实际上在`ServeHTTP ()`的内部调用了我们的`sayHello()`。

## 总结

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

有一个需要注意的点： `DefaultServeMux`和路由对应的处理方法`handler`都实现了`ServeHTTP`接口，他们俩都有`ServeHTTP`方法，但是方法要达到的目的不同，在`DefaultServeMux`的`ServeHttp()`里会执行路由对应的处理`handler`的`ServeHttp()`。

## 自定义个简单的路由

```go
package mux

import (
    "net/http"
    "strings"
)

type muxEntry struct {
    h TesthandleFunc
}

type TesthandleFunc func(http.ResponseWriter, *http.Request)

type TestHandler struct {
    routes map[string]map[string]muxEntry
}


func (h *TestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    method := strings.ToUpper(r.Method)
    path := r.URL.Path
    if route, ok := h.routes[method]; ok {
        if entry, ok := route[path]; ok {
            entry.h(w, r)
            return
        }
    }
    w.WriteHeader(http.StatusNotFound)
}

func Newhandler() *TestHandler {
    return &TestHandler{routes: make(map[string]map[string]muxEntry)}
}

func (h *TestHandler) Handle(method, path string, handler TesthandleFunc) {
    method = strings.ToUpper(method)
    if _, ok := h.routes[method]; !ok {
        h.routes[method] = make(map[string]muxEntry)
    }
    h.routes[method][path] = muxEntry{handler}
}
```

```go
package main

import (
    "fmt"
    "net/http"
    "study/mux"
)

func main() {
    handler := mux.Newhandler()
    handler.Handle("GET", "/hello", func(rw http.ResponseWriter, r *http.Request) {
        rw.Write([]byte("Hello World"))
    })
    handler.Handle("Post", "/hello/world", func(rw http.ResponseWriter, r *http.Request) {
        fmt.Fprintln(rw, "你好")
    })
    http.ListenAndServe(":9002", handler)
}
```

自定义context

```go
package router

import (
    "encoding/json"
    "net/http"
    "strings"
)

type Context struct {
    w http.ResponseWriter
    r *http.Request
}

func (c *Context) Json(code int, v interface{}) {
    c.w.Header().Set("Content-Type", "application/json")
    c.w.WriteHeader(code)
    s, _ := json.Marshal(v)
    c.w.Write(s)
}

type Routerfunc func(c *Context)

type RouterHandler struct {
    routes map[string]map[string]Routerfunc
}

func NewRouterHandler() *RouterHandler {
    return &RouterHandler{routes: make(map[string]map[string]Routerfunc)}
}

func (h *RouterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    method := strings.ToUpper(r.Method)
    path := r.URL.Path
    c := &Context{w: w, r: r}
    if route, ok := h.routes[method]; ok {
        if h, ok := route[path]; ok {
            h(c)
            return
        }
    }
    w.WriteHeader(http.StatusNotFound)
}

func (h *RouterHandler) Handle(method, path string, handler Routerfunc) {
    method = strings.ToUpper(method)
    if _, ok := h.routes[method]; !ok {
        h.routes[method] = make(map[string]Routerfunc)
    }
    h.routes[method][path] = handler
}

func (r *RouterHandler) Run(addr string) error {
    return http.ListenAndServe(addr, r)
}
```

## Gin

```go
type Engine struct {
    RouterGroup

    pool     sync.Pool
    trees    methodTrees
}// trie

type RouterGroup struct {
    basePath string
    engine   *Engine
}

func (engine *Engine) ServeHTTP(w http.ResponseWriter, req *http.Request) {
    c := engine.pool.Get().(*Context) // 从pool 拿出一个context
    c.writermem.reset(w) // 记录http.ResponseWriter 及 *http.Request
    c.Request = req
    c.reset() // 重置上一个留下的值

    engine.handleHTTPRequest(c)

    engine.pool.Put(c) // 把用完的context放回池子
}
// get: /bac
```

![5BD3C0FE-8543-42AE-AA05-D60B7A249A09.png](/images/6c261f0b5937d728d3763beaf08f85eea6999091.png)

添加路由

```go
func (group *RouterGroup) handle(httpMethod, relativePath string, handlers HandlersChain) IRoutes {
    absolutePath := group.calculateAbsolutePath(relativePath)
    handlers = group.combineHandlers(handlers)
    group.engine.addRoute(httpMethod, absolutePath, handlers)
    return group.returnObj()
}
```

Context

```go
type Context struct {
    Request   *http.Request
    Writer    ResponseWriter

    Params   Params
    handlers HandlersChain
    index    int8
    fullPath string

    engine       *Engine
    params       *Params
    skippedNodes *[]skippedNode

    // This mutex protect Keys map
    mu sync.RWMutex

    // Keys is a key/value pair exclusively for the context of each request.
    Keys map[string]interface{}

    // Errors is a list of errors attached to all the handlers/middlewares who used this context.
    Errors errorMsgs

    // Accepted defines a list of manually accepted formats for content negotiation.
    Accepted []string

    // queryCache use url.ParseQuery cached the param query result from c.Request.URL.Query()
    queryCache url.Values

    // formCache use url.ParseQuery cached PostForm contains the parsed form data from POST, PATCH,
    // or PUT body parameters.
    formCache url.Values

    // SameSite allows a server to define a cookie attribute making it impossible for
    // the browser to send this cookie along with cross-site requests.
    sameSite http.SameSite
}

func (c *Context) Next() {
    c.index++
    for c.index < int8(len(c.handlers)) {
        c.handlers[c.index](c)
        c.index++
    }
}
```

```go
func (engine *Engine) handleHTTPRequest(c *Context) {
    httpMethod := c.Request.Method
    rPath := c.Request.URL.Path
    unescape := false
    if engine.UseRawPath && len(c.Request.URL.RawPath) > 0 {
        rPath = c.Request.URL.RawPath
        unescape = engine.UnescapePathValues
    }

    if engine.RemoveExtraSlash {
        rPath = cleanPath(rPath)
    }

    // Find root of the tree for the given HTTP method
    t := engine.trees
    for i, tl := 0, len(t); i < tl; i++ {
        if t[i].method != httpMethod {
            continue
        }
        root := t[i].root
        // Find route in tree
        value := root.getValue(rPath, c.params, c.skippedNodes, unescape)
        if value.params != nil {
            c.Params = *value.params
        }
        if value.handlers != nil {
            c.handlers = value.handlers
            c.fullPath = value.fullPath
            c.Next()
            c.writermem.WriteHeaderNow()
            return
        }
        if httpMethod != http.MethodConnect && rPath != "/" {
            if value.tsr && engine.RedirectTrailingSlash {
                redirectTrailingSlash(c)
                return
            }
            if engine.RedirectFixedPath && redirectFixedPath(c, root, engine.RedirectFixedPath) {
                return
            }
        }
        break
    }

    if engine.HandleMethodNotAllowed {
        for _, tree := range engine.trees {
            if tree.method == httpMethod {
                continue
            }
            if value := tree.root.getValue(rPath, nil, c.skippedNodes, unescape); value.handlers != nil {
                c.handlers = engine.allNoMethod
                serveError(c, http.StatusMethodNotAllowed, default405Body)
                return
            }
        }
    }
    c.handlers = engine.allNoRoute
    serveError(c, http.StatusNotFound, default404Body)
}
```
