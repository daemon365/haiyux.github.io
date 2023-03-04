---
title: "Go Mod"
date: 2020-10-20T17:26:32+08:00
draft: false
toc: true
categories: [go]
tags: [golang]
authors:
    - haiyux
featuredImagePreview: /img/go.webp
---


go module是 Go1.11版本之后官方推出的版本管理工具，并且从Go1.13版本开始，go module将是Go语言默认的依赖管理工具。

## GO111MODULE

要启用go module支持首先要设置环境变量GO111MODULE，通过它可以开启或关闭模块支持，它有三个可选值：off、on、auto，默认值是auto。

1.  GO111MODULE=off禁用模块支持，编译时会从GOPATH和vendor文件夹中查找包。

2.  GO111MODULE=on启用模块支持，编译时会忽略GOPATH和vendor文件夹，只根据 go.mod下载依赖。

3.  GO111MODULE=auto，当项目在$GOPATH/src外且项目根目录有go.mod文件时，开启模块支持。

简单来说，设置GO111MODULE=on之后就可以使用go module了，以后就没有必要在GOPATH中创建项目了，并且还能够很好的管理项目依赖的第三方包信息。

使用 go module 管理依赖后会在项目根目录下生成两个文件go.mod和go.sum。

## GOPROXY

Go1.11之后设置GOPROXY命令为：

```bash
1 export GOPROXY=https://goproxy.cn
```

Go1.13之后GOPROXY默认值为https://proxy.golang.org，在国内是无法访问的，所以十分建议大家设置GOPROXY，这里我推荐使用[goproxy.cn](https://studygolang.com/topics/10014)。

```bash
go env -w GOPROXY=https://goproxy.cn,direct
```

## go mod命令

常用的go mod命令如下：

1. go mod download    下载依赖的module到本地cache（默认为$GOPATH/pkg/mod目录）
2.  go mod edit       编辑go.mod文件 
3. go mod graph       打印模块依赖图 
4. go mod init       初始化当前文件夹, 创建go.mod文件 
5. go mod tidy       增加缺少的module，删除无用的module 
6. go mod vendor     将依赖复制到vendor下 
7. go mod verify     校验依赖 
8. go mod why         解释为什么需要依赖

## go.mod

go.mod文件记录了项目所有的依赖信息，其结构大致如下：

```go
module test 
go 1.15  
require (  
		github.com/DeanThompson/ginpprof v0.0.0-20190408063150-3be636683586 
		github.com/gin-gonic/gin v1.4.0   		
		github.com/go-sql-driver/mysql v1.4.1 
    github.com/jmoiron/sqlx v1.2.0 10 
    github.com/satori/go.uuid v1.2.0 
    google.golang.org/appengine v1.6.1 // indirect 12 
)
```

其中，

*   module用来定义包名

*   require用来定义依赖包及版本

*   indirect表示间接引用

### 依赖的版本

go mod支持语义化版本号，比如go get foo@v1.2.3，也可以跟git的分支或tag，比如go get foo@master，当然也可以跟git提交哈希，比如go get foo@e3702bed2。关于依赖的版本支持以下几种格式：

```
gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 
gopkg.in/vmihailenco/msgpack.v2 v2.9.1 gopkg.in/yaml.v2 v2.2.1 
github.com/tatsushid/go-fastping v0.0.0-20160109021039-d7bb493dee3e latest
```

### replace

在国内访问golang.org/x的各个包都需要***，你可以在go.mod中使用replace替换成github上对应的库。

```
replace (  
	golang.org/x/crypto v0.0.0-20180820150726-614d502a4dac => github.com/golang/crypto v0.0.0-20180820150726-614d502a4dac  
	golang.org/x/net v0.0.0-20180821023952-922f4815f713 => github.com/golang/net v0.0.0-20180826012351-8a410e7b638d  
	golang.org/x/text v0.3.0 => github.com/golang/text v0.3.0 
)
```

## go get

在项目中执行go get命令可以下载依赖包，并且还可以指定下载的版本。

1.  运行go get -u将会升级到最新的次要版本或者修订版本(x.y.z, z是修订版本号， y是次要版本号)

2.  运行go get -u=patch将会升级到最新的修订版本

3.  运行go get package@version将会升级到指定的版本号version

如果下载所有依赖可以使用go mod download命令。

## 整理依赖

我们在代码中删除依赖代码后，相关的依赖库并不会在go.mod文件中自动移除。这种情况下我们可以使用go mod tidy命令更新go.mod中的依赖关系。

## go mod edit

### 格式化

因为我们可以手动修改go.mod文件，所以有些时候需要格式化该文件。Go提供了一下命令：

```bash
go mod edit -fmt
```

### 添加依赖项

```bash
go mod edit -require=golang.org/x/text
```

### 移除依赖项

如果只是想修改go.mod文件中的内容，那么可以运行go mod edit -droprequire=package path，比如要在go.mod中移除golang.org/x/text包，可以使用如下命令：

```bash
go mod edit -droprequire=golang.org/x/text
```

关于go mod edit的更多用法可以通过go help mod edit查看。

## 在项目中使用go module

### 既有项目

如果需要对一个已经存在的项目启用go module，可以按照以下步骤操作：

1.  在项目目录下执行go mod init，生成一个go.mod文件。

2.  执行go get，查找并记录当前项目的依赖，同时生成一个go.sum记录每个依赖库的版本和哈希值。

### 新项目

对于一个新创建的项目，我们可以在项目文件夹下按照以下步骤操作：

1.  执行go mod init 项目名命令，在当前项目文件夹下创建一个go.mod文件。

2.  手动编辑go.mod中的require依赖项或执行go get自动发现、维护依赖。

## 文章转自
- [https://www.liwenzhou.com/posts/Go/go_dependency/](https://www.liwenzhou.com/posts/Go/go_dependency/)