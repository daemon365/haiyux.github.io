---
title: "Go命令行工具cobra"
date: 2023-03-01T23:40:33+08:00
draft: false
toc: true
categories: 
  - operations
  - go
tags: 
  - cobra
authors:
    - haiyux

---

## 关于

Cobra 是 Go 的 CLI 框架。它包含一个用于创建功能强大的现代 CLI 应用程序的库，以及一个用于快速生成基于 Cobra 的应用程序和命令文件的工具。

Cobra 由 Go 项目成员和 hugo 作者 [spf13](https://github.com/spf13) 创建，已经被许多流行的 Go 项目采用，比如 kubernetes、docker等

## 特性

- 简单的基于子命令的 CLIs：`app server`、`app fetch` 等；
- 完全兼容 [POSIX（可移植操作系统接口）](https://zh.wikipedia.org/wiki/%E5%8F%AF%E7%A7%BB%E6%A4%8D%E6%93%8D%E4%BD%9C%E7%B3%BB%E7%BB%9F%E6%8E%A5%E5%8F%A3) 的标志（包括短版和长版）
- 嵌套子命令
- 全局、局部和级联的标志
- 使用 `cobra init appname` 和 `cobra add cmdname` 轻松生成应用程序和命令
- 智能提示（`app srver` ...did you mean `app server`）
- 自动生成命令和标志的帮助
- 自动识别 `-h`、`--help` 等帮助标识
- 自动为你的应用程序生成的 bash 自动完成
- 自动为你的应用程序生成 man 手册
- 命令别名，以便你可以更改内容而不会破坏它们
- 定义自己的帮助，用法等的灵活性。
- 可选与 [viper](https://github.com/spf13/viper) 紧密集成，可用于 [12factor](https://12factor.net/zh_cn/) 应用程序

## 概念

Cobra 构建在命令（commands）、参数（arguments）和 标志（flags）上。

**Commands** 代表动作，**Args** 是事物，**Flags** 是这些动作的修饰符。

最好的应用程序在使用时会像句子一样读起来。用户将知道如何使用该应用程序，因为他们将自然地了解如何使用它。

遵循的模式是 `APPNAME VERB NOUN --ADJECTIVE`。 或 `APPNAME COMMAND ARG --FLAG`

一些真实的例子可以更好地说明这一点。

在以下示例中，`server` 是命令，`port` 是标志：

```sh
hugo server --port=1313
```

在此命令中，我们告诉 Git 克隆 url 的内容：

```sh
git clone URL --bare
```

### 命令（Command）

命令是应用程序的核心。应用程序提供的每一个交互都包含在 Command 中。一个命令可以有子命令和可选的运行一个动作。

在上面的示例中，`server` 是命令。

[Cobra.Command API](https://pkg.go.dev/github.com/spf13/cobra#Command))

### 标志（Flags）

一个标志是一种修饰命令行为的方式。Cobra 支持完全符合 [https://zh.wikipedia.org/wiki/%E5%8F%AF%E7%A7%BB%E6%A4%8D%E6%93%8D%E4%BD%9C%E7%B3%BB%E7%BB%9F%E6%8E%A5%E5%8F%A3) 包。

Cobra 命令可以定义一直保留到子命令的标志和仅可用于该命令的标志。

在上面的例子中，`port` 是标志。

标志的功能是 [pflag](https://github.com/spf13/pflag) 库提供的，该库是一个标准库的 fork，在维护相同接口的基础上兼容了 [POSIX（可移植操作系统接口）](https://zh.wikipedia.org/wiki/%E5%8F%AF%E7%A7%BB%E6%A4%8D%E6%93%8D%E4%BD%9C%E7%B3%BB%E7%BB%9F%E6%8E%A5%E5%8F%A3)。

## 简单使用

```go
// 目录结构
├── add
│   └── add.go
├── go.mod
├── go.sum
└── main.go
```

```go
// main.go
package main

import (
	"log"
	"test/add"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "test",
	Short:   "测试",
	Long:    `我要写博客做个测试呢,这是个常提示`,
	Version: "v1.1",
}

func init() {
	rootCmd.AddCommand(add.CmdAdd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

```

```go
// add/add.go
package add

import (
	"fmt"

	"github.com/spf13/cobra"
)

var CmdAdd = &cobra.Command{
	Use:   "add",
	Short: "新键",
	Long:  "新建个文件",
	RunE:  RunE,
}

var path string

func init() {
	CmdAdd.Flags().StringVarP(&path, "path", "p", path, "file path")
}

func RunE(cmd *cobra.Command, args []string) error {
	fmt.Println("假装创建个文件 path=", path)
	return nil
}

```

执行结果

```bash
# go run main.go --help
我要写博客做个测试呢,这是个常提示

Usage:
  test [command]

Available Commands:
  add         新键
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command

Flags:
  -h, --help      help for test
  -v, --version   version for test

Use "test [command] --help" for more information about a command.

# go run main.go add --help
新建个文件

Usage:
  test add [flags]

Flags:
  -h, --help          help for add
  -p, --path string   file path
  
# go run main.go add --path=/user/pass 
假装创建个文件 path= /user/pass

# go run main.go --version
test version v1.1
```

## Command参数

例子中的`cobra.Command`是个结构体，有很多字段，都是做什么用的呢？

这些参数是Go语言中`cobra`库中的`Command`结构体的字段，用于定义命令行工具的行为和选项。它们的作用如下：

- `Use`: 命令名称。

- `Aliases`: 命令的别名。

- `SuggestFor`: 命令建议使用的单词列表。

- `Short`: 命令简短描述。

- `GroupID`: 命令所属的命令组。

- `Long`: 命令详细描述。

- `Example`: 命令的使用示例。

- `ValidArgs`: 命令接受的参数列表。

- `ValidArgsFunction`: 命令用于提供动态参数补全的函数。

- `Args`: 命令的位置参数列表。

- `ArgAliases`: 位置参数的别名。

- `BashCompletionFunction`: 生成Bash补全的函数。

- `Deprecated`: 命令是否已经过时的标志。

- `Annotations`: 命令的附加注释信息。

- `Version`: 命令版本号。

- `PersistentPreRun`: 每次执行该命令之前都会执行的函数。

- `PersistentPreRunE`: 每次执行该命令之前都会执行的返回错误的函数。

- `PreRun`: 每次执行该命令之前都会执行的函数。

- `PreRunE`: 每次执行该命令之前都会执行的返回错误的函数。

- `Run`: 执行命令的函数。

- `RunE`: 执行命令的返回错误的函数。

- `PostRun`: 每次执行该命令之后都会执行的函数。

- `PostRunE`: 每次执行该命令之后都会执行的返回错误的函数。

- `PersistentPostRun`: 每次执行该命令之后都会执行的函数。

- `PersistentPostRunE`: 每次执行该命令之后都会执行的返回错误的函数。

- `FParseErrWhitelist` : 忽略特定的解析错误

- `CompletionOptions ` :控制 shell 自动完成的选项

- `TraverseChildren `: 解析父命令的标志后再执行子命令

- `Hidden` : 隐藏命令，不在可用命令列表中显示

- `SilenceErrors` : 静默下游错误

- `SilenceUsage` : 静默错误时不显示用法

- `DisableFlagParsing` : 禁用标志解析

- `DisableAutoGenTag` : 禁用自动生成的标记

- `DisableFlagsInUseLine` : 在打印帮助或生成文档时禁用“[flags]”在用法行中的添加

- `DisableSuggestions` : 禁用基于Levenshtein距离的建议

- `SuggestionsMinimumDistance` : 显示建议的最小Levenshtein距离

  

## Reference

- https://juejin.cn/post/6924541628031959047
- [Cobra. Dev](https://cobra.dev/)
