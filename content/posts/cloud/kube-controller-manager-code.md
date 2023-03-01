---
title: "kube-controller-manager 代码走读"
date: 2023-03-01T21:39:58+08:00
draft: false
toc: true
categories: 
  - cloud
tags: 
  - kubernetes
  - controller
authors:
    - haiyux

---

## 介绍

这篇文章是关于`kube-controller-manager`的代码实现方式的介绍。它不包含每个`controller`的原理，只介绍了如何启动各个`controller`。代码位置在：`https://github.com/kubernetes/kubernetes/blob/master/cmd/kube-controller-manager`。

## 启动函数

```go
func main() {
	command := app.NewControllerManagerCommand()
	code := cli.Run(command)
	os.Exit(code)
}
```

`app.NewControllerManagerCommand()` 函数返回一个 `cmd *cobra.Command` 对象，该对象是一个命令行参数的集合。这个对象可以让你将命令绑定到其中，以便在启动时接受各种参数。例如，你可以使用该对象指定 `api-server` 证书的位置，或者指定每个控制器要启动的工作进程数量等。

`cmd *cobra.Command` 对象来源于 `spf13/cobra` 包，这个包是一个用于现代 Go CLI 交互的命令行工具。使用 `cmd *cobra.Command` 对象，你可以轻松地将命令行参数集成到你的应用程序中，以方便用户在启动时配置应用程序的各种选项。

在实际应用程序中，你可以将 `cmd *cobra.Command` 对象与其他应用程序逻辑相结合，以便在运行时自动执行一些操作，例如根据命令行参数初始化应用程序的配置等。这个功能非常有用，特别是当你需要在应用程序启动时进行一些特殊处理时。

`cli.Run(command)` 是一个自定义函数，它的作用是启动 `cmd *cobra.Command` 对象并执行其中的命令行参数。在这之前，它还可以进行一些初始化操作，例如初始化日志、设置日志级别、设置日志格式等。这些操作可以确保应用程序在启动时能够正确地记录日志，并且可以方便地进行故障排除和调试。

## NewControllerManagerCommand

待更新

## Run

```go
func Run(cmd *cobra.Command) int {
	if logsInitialized, err := run(cmd); err != nil {
		if !logsInitialized {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		} else {
			klog.ErrorS(err, "command failed")
		}
		return 1
	}
	return 0
}
```

1. 调用`run`函数，它的作用是启动 `cmd` 命令并执行其中的命令行参数
2. 在执行过程中可能会出现错误，这时我们需要记录日志以便调试和故障排除。如果出现了错误，那么 `logsInitialized` 变量用于判断日志是否已经被成功初始化。如果成功，我们会使用 `klog` 来记录日志，如果没有成功，我们会使用标准错误输出来记录日志。
3. 我们会根据程序执行的状态（成功或失败）设置返回值，以便后续处理。如果发生了错误，返回值为 1，否则为 0。外面的 `os.Exit(code)` 用于设置程序的返回值。
4. 整个流程大致如下：
   - 初始化日志。
   - 执行命令行参数。
   - 如果出现错误，记录日志并返回错误信息。
   - 根据程序执行状态设置返回值。

### run

```go

func run(cmd *cobra.Command) (logsInitialized bool, err error) {
	rand.Seed(time.Now().UnixNano())
	defer logs.FlushLogs()

	cmd.SetGlobalNormalizationFunc(cliflag.WordSepNormalizeFunc)

	if !cmd.SilenceUsage {
		cmd.SilenceUsage = true
		cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {

			c.SilenceUsage = false
			return err
		})
	}

	cmd.SilenceErrors = true

	logs.AddFlags(cmd.PersistentFlags())

	switch {
	case cmd.PersistentPreRun != nil:
		pre := cmd.PersistentPreRun
		cmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
			logs.InitLogs()
			logsInitialized = true
			pre(cmd, args)
		}
	case cmd.PersistentPreRunE != nil:
		pre := cmd.PersistentPreRunE
		cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
			logs.InitLogs()
			logsInitialized = true
			return pre(cmd, args)
		}
	default:
		cmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
			logs.InitLogs()
			logsInitialized = true
		}
	}

	err = cmd.Execute()
	return
}
```

1. 定义了一个名为`run`的函数，该函数接受一个指向`cobra.Command`类型的参数`cmd`，并返回两个值，一个是`logsInitialized`的布尔值，另一个是`err`的错误值，上边用到了。

2. `defer logs.FlushLogs()` : 刷新缓存并清理日志记录器。日志记录是通过 `klog` 包实现的。日志记录器在记录日志时，有时会将日志缓存在本地，等待达到一定量后再进行批量写入。`logs.FlushLogs()` 会将这些缓存中的日志写入文件中，并清空这些日志缓存，以确保在程序退出前将所有日志写入磁盘。这可以避免由于程序异常崩溃或者日志记录出错而导致丢失部分日志记录。

3. `cmd.SetGlobalNormalizationFunc(cliflag.WordSepNormalizeFunc)`：`cmd.SetGlobalNormalizationFunc`为cobra功能，作用是对标志参数名称进行规范化，以保证在处理参数时，不会因为名称大小写等原因导致出现错误。这里就是把所有的`_`替换成"-"。

   ```go
   // WordSepNormalizeFunc changes all flags that contain "_" separators
   func WordSepNormalizeFunc(f *pflag.FlagSet, name string) pflag.NormalizedName {
   	if strings.Contains(name, "_") {
   		return pflag.NormalizedName(strings.Replace(name, "_", "-", -1))
   	}
   	return pflag.NormalizedName(name)
   }
   ```

4. `SilenceUsage` 和 `SilenceErrors` 分别为反生错误时时候输出用法信息和错误信息。这里设置为`true`是避免删除无用信息对错误本身的信息进行干扰。错误信息由自己日志输出。

   ```go
   if !cmd.SilenceUsage {
   		cmd.SilenceUsage = true
   		cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
   			// Re-enable usage printing.
   			c.SilenceUsage = false
   			return err
   		})
   	}
   
   	// In all cases error printing is done below.
   	cmd.SilenceErrors = true
   ```

5. `	logs.AddFlags(cmd.PersistentFlags())`：向指定的 `pflag.FlagSet` 添加日志输出相关的标志。通过添加这些标志，可以方便地控制日志输出的级别、格式、输出位置等行为。

6. 这段代码是针对 `cmd` 命令设置 `PersistentPreRun` 钩子函数的，该函数会在执行子命令之前被调用。这段代码的作用是在执行子命令之前，先初始化日志，以确保后续的日志输出操作能够正常工作

   - 判断 `cmd` 是否设置了 `PersistentPreRun` 钩子函数，如果设置了，则先将该钩子函数保存起来，然后重新设置 `cmd` 的 `PersistentPreRun` 钩子函数，将原有的钩子函数包装在新的钩子函数内部，并在包装函数中加入了一个初始化日志的操作。
   - 如果 `cmd` 设置了 `PersistentPreRunE` 钩子函数，也会执行相似的操作，但是包装函数需要返回一个错误类型。
   - 如果 `cmd` 没有设置 `PersistentPreRun` 和 `PersistentPreRunE` 钩子函数，则设置一个默认的钩子函数，也是将原有的钩子函数包装在新的钩子函数内部，并在包装函数中加入了一个初始化日志的操作。

   ```go
   switch {
   	case cmd.PersistentPreRun != nil:
   		pre := cmd.PersistentPreRun
   		cmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
   			logs.InitLogs()
   			logsInitialized = true
   			pre(cmd, args)
   		}
   	case cmd.PersistentPreRunE != nil:
   		pre := cmd.PersistentPreRunE
   		cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
   			logs.InitLogs()
   			logsInitialized = true
   			return pre(cmd, args)
   		}
   	default:
   		cmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
   			logs.InitLogs()
   			logsInitialized = true
   		}
   	}
   ```

7. `err = cmd.Execute()` ：执行`cmd`

## Reference

- [kubernetes/cmd/kube-controller-manager at master · kubernetes/kubernetes (github.com)](https://github.com/kubernetes/kubernetes/tree/master/cmd/kube-controller-manager)
- [spf13/cobra: A Commander for modern Go CLI interactions (github.com)](https://github.com/spf13/cobra)
- [spf13/pflag: Drop-in replacement for Go's flag package, implementing POSIX/GNU-style --flags. (github.com)](https://github.com/spf13/pflag)
