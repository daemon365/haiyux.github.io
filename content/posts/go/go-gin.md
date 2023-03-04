---
title: "Go Gin框架介绍及使用"
date: 2021-05-09T14:53:19+08:00
draft: false
toc: true
categories: [go]
tags: [golang,http]
authors:
    - haiyux
featuredImagePreview: /img/go.webp
---

## Gin框架介绍

* 基于[httprouter](https://github.com/julienschmidt/httprouter)开发的Web框架。
* [中文文档](https://gin-gonic.com/zh-cn/docs/)，齐全。
* 简单易用的轻量级框架。

## Gin框架安装

```bash
go get -u github.com/gin-gonic/gin
```

**实例:**

```go
package main
import (
    "fmt"
    "github.com/gin-gonic/gin"
)
func main() {

    r := gin.Default()
    // 创建一个默认的路由引擎
    // 也可以用gin.New() gin.Default()多用了日志和panic的recover中间件
    r.GET("/helloworld", func(c *gin.Context) {
        c.JSON(200, gin.H{
            // c.JSON：返回JSON格式的数据
            "msg": "Hello world!",
        })
    })
    err := r.Run("127.0.0.1:8001")
    // 启动HTTP服务，默认在127.0.0.1:8001启动服务
    if err != nil {
        fmt.Println("run gin field")
        return
    }
}
```

![](/images/2344773-20210907095947044-1320655711.png)

## RESTful API

REST与技术无关，代表的是一种软件架构风格，REST是Representational State Transfer的简称，中文翻译为“表征状态转移”或“表现层状态转化”。

简单来说，REST的含义就是客户端与Web服务器之间进行交互的时候，使用HTTP协议中的4个请求方法代表不同的动作。

* GET用来获取资源
* POST用来新建资源
* PUT用来更新资源
* DELETE用来删除资源。

只要API程序遵循了REST风格，那就可以称其为RESTful API。目前在前后端分离的架构中，前后端基本都是通过RESTful API来进行交互。

例如，我们现在要编写一个管理书籍的系统，我们可以查询对一本书进行查询、创建、更新和删除等操作，我们在编写程序的时候就要设计客户端浏览器与我们Web服务端交互的方式和路径。按照经验我们通常会设计成如下模式：

| 请求方法 | URL          | 含义     |
| ---- | ------------ | ------ |
| GET  | /book        | 查询书籍信息 |
| POST | /create_book | 创建书籍记录 |
| POST | /update_book | 更新书籍信息 |
| POST | /delete_book | 删除书籍信息 |

同样的需求我们按照RESTful API设计如下：

| 请求方法   | URL   | 含义     |
| ------ | ----- | ------ |
| GET    | /book | 查询书籍信息 |
| POST   | /book | 创建书籍记录 |
| PUT    | /book | 更新书籍信息 |
| DELETE | /book | 删除书籍信息 |

Gin框架支持开发RESTful API的开发。

```go
func main() {
    r := gin.Default()
    r.GET("/book", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "message": "GET",
        })
    })
    r.POST("/book", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "message": "POST",
        })
    })
    r.PUT("/book", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "message": "PUT",
        })
    })
    r.DELETE("/book", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "message": "DELETE",
        })
    })
}
```

开发RESTful API的时候我们通常使用[Postman](https://www.getpostman.com/)来作为客户端的测试工具。

## Gin渲染

### HTML渲染

我们首先定义一个存放模板文件的templates文件夹，然后在其内部按照业务分别定义一个posts文件夹和一个users文件夹。posts/index.html文件的内容如下：

```go
{{define "posts/index.html"}}
    posts/index
    {{.title}}
{{end}}
```

users/index.html文件的内容如下：

```go
{{define "users/index.html"}}
    users/index
    {{.title}}
{{end}}
```

Gin框架中使用LoadHTMLGlob()或者LoadHTMLFiles()方法进行HTML模板渲染。

```go
func main() {
    r := gin.Default()
    r.LoadHTMLGlob("templates/**/*")
    //r.LoadHTMLFiles("templates/posts/index.html", "templates/users/index.html")
    r.GET("/posts/index", func(c *gin.Context) {
        c.HTML(http.StatusOK, "posts/index.html", gin.H{
            "title": "posts/index",
        })
    })
    r.GET("users/index", func(c *gin.Context) {
        c.HTML(http.StatusOK, "users/index.html", gin.H{
            "title": "users/index",
        })
    })
    r.Run(":8080")
}
```

### 静态文件处理

当我们渲染的HTML文件中引用了静态文件时，我们只需要按照以下方式在渲染页面前调用gin.Static方法即可。

```go
func main() {
    r := gin.Default()
    r.Static("/static", "./static")
    r.LoadHTMLGlob("templates/**/*")
   ...
    r.Run(":8080")
}
```

### 补充文件路径处理

关于模板文件和静态文件的路径，我们需要根据公司/项目的要求进行设置。可以使用下面的函数获取当前执行程序的路径。

```go
func getCurrentPath() string {
    if ex, err := os.Executable(); err == nil {
        return filepath.Dir(ex)
    }
    return "./"
}
```

### JSON渲染

```go
func main() {
    r := gin.Default()
    // gin.H 是map[string]interface{}的缩写
    r.GET("/someJSON", func(c *gin.Context) {
        // 方式一：自己拼接JSON
        c.JSON(http.StatusOK, gin.H{"message": "Hello world!"})
    })
    r.GET("/moreJSON", func(c *gin.Context) {
        // 方法二：使用结构体
        var msg struct {
            Name    string `json:"user"`
            Message string
            Age     int
        }
        msg.Name = "zhy"
        msg.Message = "Hello world!"
        msg.Age = 18
        c.JSON(http.StatusOK, msg)
    })
    r.Run(":8080")
}
```

### XML渲染

注意需要使用具名的结构体类型。

```go
func main() {
    r := gin.Default()
    // gin.H 是map[string]interface{}的缩写
    r.GET("/someXML", func(c *gin.Context) {
        // 方式一：自己拼接JSON
        c.XML(http.StatusOK, gin.H{"message": "Hello world!"})
    })
    r.GET("/moreXML", func(c *gin.Context) {
        // 方法二：使用结构体
        type MessageRecord struct {
            Name    string
            Message string
            Age     int
        }
        var msg MessageRecord
        msg.Name = "小王子"
        msg.Message = "Hello world!"
        msg.Age = 18
        c.XML(http.StatusOK, msg)
    })
    r.Run(":8080")
}
```

### YMAL渲染

```go
r.GET("/someYAML", func(c *gin.Context) {
    c.YAML(http.StatusOK, gin.H{"message": "ok", "status": http.StatusOK})
})
```

### protobuf渲染

```protobuf
// protobuf文件
syntax = "proto3";
package models;
message hello {
    string content = 1;
}
```

```go
package main
import (
    "net/http"
    "test/models"
    "github.com/gin-gonic/gin"
)
func main() {
    r := gin.Default()
    r.GET("/hello",func (c *gin.Context)  {
        res := &models.Hello{
            Content: "你好",
        }
        c.ProtoBuf(http.StatusOK,res)
    })
    _ = r.Run("127.0.0.1:8001")
}
```

## 获取参数

### 获取querystring参数

querystring指的是URL中?后面携带的参数，例如：/user?username=赵海宇&address=地球一角。

1. c.DefaultQuery有默认值 如果没有传去默认值
2. c.Query没有默认值 如果没传 为空

```go
package main
import (
    "net/http"
    "github.com/gin-gonic/gin"
)
func main() {
    r := gin.Default()
    r.GET("/user", func(c *gin.Context) {
        username := c.DefaultQuery("username", "zhy")
        address := c.Query("address")
        c.JSON(http.StatusOK, gin.H{
            "username": username,
            "address":  address,
        })
    })
    _ = r.Run("127.0.0.1:8001")
}
```

### 获取form参数

请求的数据通过form表单来提交，例如向/user发送一个POST请求，获取请求数据的方式如下：c.PostForm

```go
package main
import (
    "net/http"
    "github.com/gin-gonic/gin"
)
func main() {
    r := gin.Default()
    r.POST("/user", func(c *gin.Context) {
        username := c.PostForm("username")
        address := c.PostForm("address")
        c.JSON(http.StatusOK, gin.H{
            "username": username,
            "address":  address,
        })
    })
    _ = r.Run("127.0.0.1:8001")
}
```

### 获取path参数

请求的参数通过URL路径传递，例如：/user/zhaohaiyu/地球一角/路由:/user/:username/:address方法:c.Param

```go
package main
import (
    "net/http"
    "github.com/gin-gonic/gin"
)
func main() {
    r := gin.Default()
    r.GET("/user/:username/:address", func(c *gin.Context) {
        username := c.Param("username")
        address := c.Param("address")
        c.JSON(http.StatusOK, gin.H{
            "username": username,
            "address":  address,
        })
    })
    _ = r.Run("127.0.0.1:8001")
}
```

### 参数绑定

为了能够更方便的获取请求相关参数，提高开发效率，我们可以基于请求的content-type识别请求数据类型并利用反射机制自动提取请求中querystring、form表单、JSON、XML等参数到结构体中。

```go
package main
import (
    "fmt"
    "net/http"
    "github.com/gin-gonic/gin"
)
// Binding from JSON
type Login struct {
    User     string `form:"user" json:"user" binding:"required"`
    Password string `form:"password" json:"password" binding:"required"`
}
func main() {
    r := gin.Default()
    // 绑定JSON的示例 ({"user": "root", "password": "123"})
    r.POST("/loginJSON", func(c *gin.Context) {
        var login Login
        if err := c.ShouldBindJSON(&login); err == nil {
            fmt.Printf("login info:%#v\n", login)
            c.JSON(http.StatusOK, login)
        } else {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        }
    })
    // 绑定form表单示例 (user=root&password=123)
    r.POST("/loginForm", func(c *gin.Context) {
        var login Login
        // ShouldBind()会根据请求的Content-Type自行选择绑定器
        if err := c.ShouldBind(&login); err == nil {
            c.JSON(http.StatusOK, login)
        } else {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        }
    })
    // 绑定querystring示例 (user=root&password=123)
    r.GET("/loginForm", func(c *gin.Context) {
        var login Login
        // ShouldBind()会根据请求的Content-Type自行选择绑定器
        if err := c.ShouldBind(&login); err == nil {
            c.JSON(http.StatusOK, login)
        } else {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        }
    })
    _ = r.Run("127.0.0.1:8001")
}
```

## 文件上传

```go
func main() {
    router := gin.Default() // 处理multipart forms提交文件时默认的内存限制是32 MiB
    // 可以通过下面的方式修改
    // router.MaxMultipartMemory = 8 << 20 // 8 MiB
    router.POST("/upload", func(c *gin.Context) {
        // 单个文件
        file, err := c.FormFile("file")
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
            return
        }
        log.Println(file.Filename)
        dst := fmt.Sprintf("C:/tmp/%s", file.Filename) // 上传文件到指定的目录
        c.SaveUploadedFile(file, dst)
        c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("'%s' uploaded!", file.Filename)})
    })
    router.Run()
}
```

### 多个文件上传

```go
func main() {
    router := gin.Default()
    // 处理multipart forms提交文件时默认的内存限制是32 MiB
    // 可以通过下面的方式修改
    // router.MaxMultipartMemory = 8 << 20  // 8 MiB
    router.POST("/upload", func(c *gin.Context) {
        // Multipart form
        form, _ := c.MultipartForm()
        files := form.File["file"]
        for index, file := range files {
            log.Println(file.Filename)
            dst := fmt.Sprintf("C:/tmp/%s_%d", file.Filename, index)
            // 上传文件到指定的目录
            c.SaveUploadedFile(file, dst)
        }
        c.JSON(http.StatusOK, gin.H{
            "message": fmt.Sprintf("%d files uploaded!", len(files)),
        })
    })
    router.Run()
}
```

## Gin中间件

Gin框架允许开发者在处理请求的过程中，加入用户自己的钩子（Hook）函数。这个钩子函数就叫中间件，中间件适合处理一些公共的业务逻辑，比如登录校验、日志打印、耗时统计等。

Gin中的中间件必须是一个gin.HandlerFunc类型。例如我们像下面的代码一样定义一个中间件。

```go
// StatCost 是一个统计耗时请求耗时的中间件
func StatCost() gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        c.Set("name", "小王子")
        // 执行其他中间件
        c.Next()
        // 计算耗时
        cost := time.S***art)
        log.Println(cost)
    }
}
```

然后注册中间件的时候，可以在全局注册。

```go
func main() {
    // 新建一个没有任何默认中间件的路由
    r := gin.New()
    // 注册一个全局中间件
    r.Use(StatCost())

    r.GET("/test", func(c *gin.Context) {
        name := c.MustGet("name").(string)
        log.Println(name)
        c.JSON(http.StatusOK, gin.H{
            "message": "Hello world!",
        })
    })
    r.Run()
}
```

也可以给某个路由单独注册中间件。

```go
// 给/test2路由单独注册中间件（可注册多个）
    r.GET("/test2", StatCost(), func(c *gin.Context) {
        name := c.MustGet("name").(string)
        log.Println(name)
        c.JSON(http.StatusOK, gin.H{
            "message": "Hello world!",
        })
    })
```

### 重定向

#### HTTP重定向

HTTP 重定向很容易。 内部、外部重定向均支持。

```go
r.GET("/test", func(c *gin.Context) {
    c.Redirect(http.StatusMovedPermanently, "http://www.google.com/")
})
```

#### 路由重定向

路由重定向，使用HandleContext：

```go
r.GET("/test", func(c *gin.Context) {
    // 指定重定向的URL
    c.Request.URL.Path = "/test2"
    r.HandleContext(c)
})
r.GET("/test2", func(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"hello": "world"})
})
```

## Gin路由

### 普通路由

```go
r.GET("/index", func(c *gin.Context) {...})
r.GET("/login", func(c *gin.Context) {...})
r.POST("/login", func(c *gin.Context) {...})
```

此外，还有一个可以匹配所有请求方法的Any方法如下：

```go
r.Any("/test", func(c *gin.Context) {...})
```

为没有配置处理函数的路由添加处理程序。默认情况下它返回404代码。

```go
r.NoRoute(func(c *gin.Context) {
        c.HTML(http.StatusNotFound, "views/404.html", nil)
    })
```

### 路由组

我们可以将拥有共同URL前缀的路由划分为一个路由组。

```go
func main() {
    r := gin.Default()
    userGroup := r.Group("/user")
    {
        userGroup.GET("/index", func(c *gin.Context) {...})
        userGroup.GET("/login", func(c *gin.Context) {...})
        userGroup.POST("/login", func(c *gin.Context) {...})
    }
    shopGroup := r.Group("/shop")
    {
        shopGroup.GET("/index", func(c *gin.Context) {...})
        shopGroup.GET("/cart", func(c *gin.Context) {...})
        shopGroup.POST("/checkout", func(c *gin.Context) {...})
    }
    r.Run()
}
```

通常我们将路由分组用在划分业务逻辑或划分API版本时。

### 路由分文件

1. 在route中初始化route和切片路由组
2. 在各个文件写路由
3. 在main中把路由函数放入函数路由组

```go
// route中go
package route
import "github.com/gin-gonic/gin"
type Option func(*gin.Engine)
var options = []Option{} // 路由函数组
// 注册app的路由配置
func Include(opts ...Option) {
    options = append(options, opts...) // 路由函数组添加函数
}
// 初始化
func Init() *gin.Engine {
    r := gin.New()
    for _, function := range options {
        function(r) // 执行路由函数组中所有函数
    }
    return r
}
```

```go
// shop中的文件
package shop
import "github.com/gin-gonic/gin"
func Routers(e *gin.Engine) {// 路由函数
    e.GET("/post", func(c *gin.Context) {
        c.String(200,"psot shop")
    })
    e.GET("/comment", func(c *gin.Context) {
        c.String(200,"comment shop")
    })
}
```

```go
// main.go
package main
import (
    "test/demo1/route"
    "test/demo1/shop"
)
func main() {
    route.Include(shop.Routers)
    // 初始化路由
    r := route.Init() 
    _ = r.Run()
}
```

### 路由原理

Gin框架中的路由使用的是[httprouter](https://github.com/julienschmidt/httprouter)这个库。

其基本原理就是构造一个路由地址的前缀树。

## 参考文章

- [https://www.liwenzhou.com/posts/Go/Gin_framework/](https://www.liwenzhou.com/posts/Go/Gin_framework/)