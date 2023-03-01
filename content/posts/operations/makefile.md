---
title: "Makefile"
date: 2020-06-12T17:30:43+08:00
draft: false
toc: true
categories: 
  - operations
tags: 
  - makefile
authors:
    - haiyux
---

## make

make是一个构建自动化工具，会在当前目录下寻找Makefile或makefile文件。如果存在相应的文件，它就会依据其中定义好的规则完成构建任务。

## makefile

什么是makefile？或许很多Winodws的程序员都不知道这个东西，因为那些Windows的IDE都为你做了这个工作，但我觉得要作一个好的和professional的程序员，makefile还是要懂。这就好像现在有这么多的HTML的编辑器，但如果你想成为一个专业人士，你还是要了解HTML的标识的含义。特别在Unix下的软件编译，你就不能不自己写makefile了，**会不会写makefile，从一个侧面说明了一个人是否具备完成大型工程的能力**。因为，makefile关系到了整个工程的编译规则。一个工程中的源文件不计数，其按****类型、功能、模块****分别放在若干个目录中，makefile定义了一系列的规则来指定，哪些文件需要先编译，哪些文件需要后编译，哪些文件需要重新编译，甚至于进行更复杂的功能操作，因为makefile就像一个Shell脚本一样，其中也可以执行操作系统的命令。makefile带来的好处就是——“自动化编译”，一旦写好，只需要一个make命令，整个工程完全自动编译，极大的提高了软件开发的效率。make是一个命令工具，是一个解释makefile中指令的命令工具，一般来说，大多数的IDE都有这个命令，比如：Delphi的make，Visual C++的nmake，Linux下GNU的make。可见，makefile都成为了一种在工程方面的编译方法。

## 规则概述

Makefile由多条规则组成，每条规则主要由两个部分组成，分别是依赖的关系和执行的命令。

其结构如下所示：

```
[target] ... : [prerequisites] ...
[command]
    ...
    ...
```

其中：

*   targets：规则的目标
*   prerequisites：可选的要生成 targets 需要的文件或者是目标。
*   command：make 需要执行的命令（任意的 shell 命令）。可以有多条命令，每一条命令占一行。

举个例子：

```yaml
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o xx
```

## 示例

```yaml
.PHONY: all build run gotool clean help
BINARY="coursemanager"
all: build
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ${BINARY}
run:
	@go run ./
gotool:
	go fmt ./
	go vet ./
clean:
	@if [ -f ${BINARY} ] ; then rm ${BINARY} ; fi
help:
	@echo "make - 格式化 Go 代码, 并编译生成二进制文件"
	@echo "make build - 编译 Go 代码, 生成二进制文件"
	@echo "make run - 直接运行 Go 代码"
	@echo "make clean - 移除二进制文件和 vim swap files"
	@echo "make gotool - 运行 Go 工具 'fmt' and 'vet'"
```

参考文章:

*   [https://www.liwenzhou.com/posts/Go/makefile/](https://www.liwenzhou.com/posts/Go/makefile/)
*   [https://blog.csdn.net/weixin_38391755/article/details/80380786](https://blog.csdn.net/weixin_38391755/article/details/80380786)
