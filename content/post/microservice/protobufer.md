---
title: "proto bufer"
date: 2020-11-28T10:33:45+08:00
draft: false
toc: true
categories: [microservice]
tags: [微服务,protobuf]
authors:
    - haiyux
---

protobuf是一种高效的数据格式，平台无关、语言无关、可扩展，可用于 RPC 系统和持续数据存储系统。

## protobuf介绍

Protobuf是Protocol Buffer的简称，它是Google公司于2008年开源的一种高效的平台无关、语言无关、可扩展的数据格式，目前Protobuf作为接口规范的描述语言，可以作为Go语言RPC接口的基础工具。

## protobuf使用

protobuf是一个与语言无关的一个数据协议，所以我们需要先编写IDL文件然后借助专用工具生成指定语言的代码，从而实现数据的序列化与反序列化过程。

大致开发流程如下： 1\. IDL编写 2\. 生成指定语言的代码 3\. 序列化和反序列化

## protobuf语法

官网：[https://developers.google.cn/protocol-buffers/docs/proto3](https://developers.google.cn/protocol-buffers/docs/proto3) (英文)

三方：[https://colobu.com/2017/03/16/Protobuf3-language-guide](https://colobu.com/2017/03/16/Protobuf3-language-guide)  (中文)

## 编译器安装

### ptotoc

mac安装：

```bash
brew info protobuf
```

cdn下载：(下载需要的版本)

[cdn下载链接](https://repo1.maven.org/maven2/com/google/protobuf/protoc/)

linux/mac 编译安装

[教程](https://github.com/protocolbuffers/protobuf/blob/master/src/README.md)

### protoc-gen-go

安装生成Go语言代码的工具

两个版本：

- github版本  `github.com/golang/protobuf/protoc-gen-go`
- google版本 `google.golang.org/protobuf/cmd/protoc-gen-go`

区别在于前者是旧版本，后者是google接管后的新版本，他们之间的API是不同的，也就是说用于生成的命令，以及生成的文件都是不一样的。

因为目前的`gRPC-go`源码中的example用的是后者的生成方式，为了与时俱进，本文也采取最新的方式。

安装：

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

## 编写IDL代码

新建一个名为person.proto的文件具体内容如下：

```protobuf
// 指定使用protobuf版本
// 此处使用v3版本
syntax = "proto3";

// 包名，通过protoc生成go文件
package address;

// go的包名 新版protoc-gen-go 必须带"/"
option go_package = "../hello";

// 性别类型 
// 枚举类型第一个字段必须为0
enum GenderType {
    SECRET = 0;
    FEMALE = 1;
    MALE = 2;
}
// 人
message Person {
    int64 id = 1;
    string name = 2;
    GenderType gender = 3;
    string number = 4;
}
// 联系簿
message ContactBook {
    repeated Person persons = 1;
}
```

## 生成go语言代码

在protobuf_demo/address目录下执行以下命令。

```bash
protoc --proto_path=./  --go_out=./ ./person.proto
```

*   --proto_path: 指定了要去哪个目录中搜索import中导入的和要编译为.go的proto文件
*   --go_out:指定了生成的go文件的目录，我在这里把go文件放到本目录中
*   person.proto， 定义了我要编译的文件是哪个文件。

此时在当前目录下会生成一个person.pb.go文件，我们的Go语言代码里就是使用这个文件。 在protobuf_demo/main.go文件中：

```go
package main

import (
	"fmt"
	"io/ioutil"
	"z/test3/person"

	"github.com/golang/protobuf/proto"
)


func main() {
	var cb person.ContactBook
	p1 := person.Person{
		Name:   "zhao",
		Gender: person.GenderType_MALE,
		Number: "12345678910",
	}
	fmt.Println(p1)
	cb.Persons = append(cb.Persons, &p1)

	data, err := proto.Marshal(&p1)
	if err != nil {
		fmt.Printf("marshal failed,err:%v\n", err)
		return
	}
	ioutil.WriteFile("./proto.dat", data, 0644)
	data2, err := ioutil.ReadFile("./proto.dat")
	if err != nil {
		fmt.Printf("read file failed, err:%v\n", err)
		return
	}
	var p2 person.Person
	proto.Unmarshal(data2, &p2)
	fmt.Println(p2)
}
```

参考文章:[https://www.liwenzhou.com/posts/Go/protobuf/](https://www.liwenzhou.com/posts/Go/protobuf/)
