---
title: Ip Tables Code
subtitle:
date: 2023-05-29T20:54:02+08:00
draft: false
toc: true
categories: [cloud]
tags: [kubernetes]
authors:
    - haiyux
featuredImagePreview: /img/preview/proxy/kube-proxy.jpg
---

## utiliptables.Interface

```go
// Interface是一个可注入的接口，用于运行iptables命令。实现必须是协程安全的。
type Interface interface {
    // EnsureChain检查指定的链是否存在，如果不存在，则创建它。如果链存在，则返回true。
    EnsureChain(table Table, chain Chain) (bool, error)
    // FlushChain清除指定的链。如果链不存在，则返回错误。
    FlushChain(table Table, chain Chain) error

    // DeleteChain删除指定的链。如果链不存在，则返回错误。
    DeleteChain(table Table, chain Chain) error

    // ChainExists测试指定的链是否存在，如果不存在或无法检查，则返回错误。
    ChainExists(table Table, chain Chain) (bool, error)

    // EnsureRule检查指定的规则是否存在，如果不存在，则创建它。如果规则存在，则返回true。
    EnsureRule(position RulePosition, table Table, chain Chain, args ...string) (bool, error)

    // DeleteRule检查指定的规则是否存在，如果存在，则删除它。
    DeleteRule(table Table, chain Chain, args ...string) error

    // IsIPv6如果管理ipv6表，则返回true。
    IsIPv6() bool

    // Protocol返回此实例正在管理的IP系列。
    Protocol() Protocol

    // SaveInto调用`iptables-save`来保存表的数据，并将结果存储在给定的缓冲区中。
    SaveInto(table Table, buffer *bytes.Buffer) error

    // Restore运行`iptables-restore`并通过[]byte传递数据。
    // table是要还原的表
    // data应该格式化为SaveInto()的输出格式
    // flush设置"--noflush"标志的存在。参见：FlushFlag
    // counters设置"--counters"标志的存在。参见：RestoreCountersFlag
    Restore(table Table, data []byte, flush FlushFlag, counters RestoreCountersFlag) error

    // RestoreAll与Restore相同，只是不指定表。
    RestoreAll(data []byte, flush FlushFlag, counters RestoreCountersFlag) error

    // Monitor通过创建标记链并轮询以检查它们是否已被删除来检测给定的iptables表是否已被外部工具（例如防火墙重新加载）清空。
    // （具体来说，它每隔一段时间轮询tables[0]，直到canary从那里被删除，然后再等待一段时间，等待canary从剩余的表中被删除。您可以通过在tables[0]中列出一个相对较空的表来优化轮询）。当检测到清空时，调用reloadFunc，以便调用者可以重新加载自己的iptables规则。
    // 如果无法创建canary链（初始或重新加载后），它将记录错误并停止监视。
    // （此函数应从goroutine中调用。）
    Monitor(canary Chain, tables []Table, reloadFunc func(), interval time.Duration, stopCh <-chan struct{})

    // HasRandomFully揭示`-j MASQUERADE`是否接受`--random-fully`选项。这对于解决Linux内核中的一个错误很有帮助，该错误有时会导致多个流映射到相同的IP:PORT，从而导致某些数据包丢失。
    HasRandomFully() bool

    // Present检查内核是否支持iptables接口
    Present() bool
}
```

### Table

```go
// Table表示不同的iptables表，如filter、nat、mangle和raw
type Table string

const (
    // TableNAT表示内置的nat表
    TableNAT Table = "nat"
    // TableFilter表示内置的filter表
    TableFilter Table = "filter"
    // TableMangle表示内置的mangle表
    TableMangle Table = "mangle"
)
```

### Chain

```go
// Chain表示不同的规则
type Chain string

const (
    // ChainPostrouting用于nat表中的源地址转换
    ChainPostrouting Chain = "POSTROUTING"
    // ChainPrerouting用于nat表中的目标地址转换
    ChainPrerouting Chain = "PREROUTING"
    // ChainOutput用于从本地发送的数据包
    ChainOutput Chain = "OUTPUT"
    // ChainInput用于传入的数据包
    ChainInput Chain = "INPUT"
    // ChainForward用于另一个网卡的数据包
    ChainForward Chain = "FORWARD"
)
```

### RulePosition

```go
// RulePosition保存iptables的-I/-A标志
type RulePosition string

const (
    // Prepend是iptables的插入标志
    Prepend RulePosition = "-I"
    // Append是iptables的追加标志
    Append RulePosition = "-A"
)
```

### FlushFlag

```go
// FlushFlag是Flush的选项标志
type FlushFlag bool

// FlushTables是FlushFlag选项标志的布尔值为true的常量
const FlushTables FlushFlag = true

// NoFlushTables是FlushFlag选项标志的布尔值为false的常量
const NoFlushTables FlushFlag = false

// RestoreCountersFlag是Restore的选项标志
type RestoreCountersFlag bool

// RestoreCounters是RestoreCountersFlag选项标志的布尔值为true的常量
const RestoreCounters RestoreCountersFlag = true

// NoRestoreCounters是RestoreCountersFlag选项标志的布尔值为false的常量
const NoRestoreCounters RestoreCountersFlag = false
```

### Protocol

```go
// Protocol定义IP协议，可以是IPv4或IPv6
type Protocol string

const (
    // ProtocolIPv4表示iptables中的IPv4协议
    ProtocolIPv4 Protocol = "IPv4"
    // ProtocolIPv6表示iptables中的IPv6协议
    ProtocolIPv6 Protocol = "IPv6"
)
```

### operation

```go
type operation string

// 定义操作类型常量
const (
	opCreateChain operation = "-N"
	opFlushChain  operation = "-F"
	opDeleteChain operation = "-X"
	opListChain   operation = "-S"
	opCheckRule   operation = "-C"
	opDeleteRule  operation = "-D"
)
```

### oether

```go
const (
    cmdIPTablesSave string = "iptables-save"
    cmdIPTablesRestore string = "iptables-restore"
    cmdIPTables string = "iptables"
    cmdIP6TablesRestore string = "ip6tables-restore"
    cmdIP6TablesSave string = "ip6tables-save"
    cmdIP6Tables string = "ip6tables"
)

// MinCheckVersion 是需要检查的最低版本。
// 低于此版本的 iptables 不支持 -C / --check 标志（用于测试规则是否存在）。
var MinCheckVersion = utilversion.MustParseGeneric("1.4.11")

// RandomFullyMinVersion 是支持 --random-fully 标志的最低版本，
// 用于完全随机化端口映射。
var RandomFullyMinVersion = utilversion.MustParseGeneric("1.6.2")

// WaitMinVersion 是支持 -w 和 -w<seconds> 标志的最低 iptables 版本。
var WaitMinVersion = utilversion.MustParseGeneric("1.4.20")

// WaitIntervalMinVersion 是支持等待间隔 useconds 的最低 iptables 版本。
var WaitIntervalMinVersion = utilversion.MustParseGeneric("1.6.1")

// WaitSecondsMinVersion 是支持等待秒数的最低 iptables 版本。
var WaitSecondsMinVersion = utilversion.MustParseGeneric("1.4.22")

// WaitRestoreMinVersion 是支持等待恢复秒数的最低 iptables 版本。
var WaitRestoreMinVersion = utilversion.MustParseGeneric("1.6.2")

// WaitString 是用于指定等待标志的常量。
const WaitString = "-w"

// WaitSecondsValue 是用于指定默认等待秒数的常量。
const WaitSecondsValue = "5"

// WaitIntervalString 是用于指定等待间隔标志的常量。
const WaitIntervalString = "-W"

// WaitIntervalUsecondsValue 是用于指定默认等待间隔微秒数的常量。
const WaitIntervalUsecondsValue = "100000"

// LockfilePath16x 是 iptables 1.6.x 版本的锁文件路径，由对 iptable 规则进行更改的任何进程获取。
const LockfilePath16x = "/run/xtables.lock"

// LockfilePath14x 是 iptables 1.4.x 版本的锁文件路径，由对 iptable 规则进行更改的任何进程获取。
const LockfilePath14x = "@xtables"
```

## runner

```go
// runner通过执行"iptables"命令实现了Interface接口。
type runner struct {
    mu sync.Mutex // 使用互斥锁来保证并发安全
    exec utilexec.Interface // 执行命令的接口
    protocol Protocol // 协议类型
    hasCheck bool // 是否支持iptables的-C选项（检查规则是否存在）
    hasRandomFully bool // 是否支持iptables的--random-fully选项
    waitFlag []string // 执行iptables命令时的等待选项
    restoreWaitFlag []string // 执行iptables-restore命令时的等待选项
    lockfilePath14x string // iptables-restore的锁文件路径（适用于iptables 1.4.x版本）
    lockfilePath16x string // iptables-restore的锁文件路径（适用于iptables 1.6.x版本）
}
```

### New

```go

// newInternal返回一个新的Interface，它将执行iptables命令，并允许调用者更改iptables-restore的锁文件路径。
func newInternal(exec utilexec.Interface, protocol Protocol, lockfilePath14x, lockfilePath16x string) Interface {
    version, err := getIPTablesVersion(exec, protocol) // 获取iptables的版本信息
    if err != nil {
        klog.InfoS("Error checking iptables version, assuming version at least", "version", MinCheckVersion, "err", err)
        version = MinCheckVersion // 如果获取版本信息失败，则假设版本至少为MinCheckVersion
    }
	if lockfilePath16x == "" {
        lockfilePath16x = LockfilePath16x  // 如果lockfilePath16x为空，则使用默认的锁文件路径
    } 
    if lockfilePath14x == "" {
        lockfilePath14x = LockfilePath14x  // 如果lockfilePath14x为空，则使用默认的锁文件路径
    }

    runner := &runner{
        exec:            exec,
        protocol:        protocol,
        hasCheck:        version.AtLeast(MinCheckVersion), // 检查是否支持-C选项
        hasRandomFully:  version.AtLeast(RandomFullyMinVersion), // 检查是否支持--random-fully选项
        waitFlag:        getIPTablesWaitFlag(version),  // 获取iptables命令的等待选项
        restoreWaitFlag: getIPTablesRestoreWaitFlag(version, exec, protocol),  // 获取iptables-restore的wait标志参数
        lockfilePath14x: lockfilePath14x,
        lockfilePath16x: lockfilePath16x,
    }
    return runner
}

// New返回一个新的Interface，它将执行iptables命令。
func New(exec utilexec.Interface, protocol Protocol) Interface {
	return newInternal(exec, protocol, "", "")
}
```

#### utilexec.Interface

```go
// Interface 是一个接口，它提供了一组 os/exec API 的子集。在需要注入可伪造/可模拟的 exec 行为时使用该接口。
type Interface interface {
    // Command 返回一个 Cmd 实例，用于运行单个命令。遵循 package os/exec 的模式。
    Command(cmd string, args ...string) Cmd
	// CommandContext 返回一个 Cmd 实例，用于运行单个命令。
    //
    // 如果上下文在命令完成之前变为完成状态，将使用提供的上下文来终止进程。例如，可以在上下文中设置超时。
    CommandContext(ctx context.Context, cmd string, args ...string) Cmd

    // LookPath 包装了 os/exec.LookPath
    LookPath(file string) (string, error)
}

// executor 在真正执行 exec() 的情况下实现了 Interface 接口。
type executor struct{}

// New 返回一个新的 Interface，它将使用 os/exec 来运行命令。
func New() Interface {
	return &executor{}
}

// Command 是 Interface 接口的一部分。
func (executor *executor) Command(cmd string, args ...string) Cmd {
	return (*cmdWrapper)(maskErrDotCmd(osexec.Command(cmd, args...)))
}

// CommandContext 是 Interface 接口的一部分。
func (executor *executor) CommandContext(ctx context.Context, cmd string, args ...string) Cmd {
	return (*cmdWrapper)(maskErrDotCmd(osexec.CommandContext(ctx, cmd, args...)))
}

// LookPath 是 Interface 接口的一部分。
func (executor *executor) LookPath(file string) (string, error) {
	path, err := osexec.LookPath(file)
	return path, handleError(maskErrDot(err))
}
```

##### Cmd

```GO
// Cmd 是一个接口，它提供了与 os/exec 中的 Cmd 非常相似的 API。随着需要更多功能，它可以扩展。由于 Cmd 是一个结构体，我们将使用 get/set 方法对来替换字段。
type Cmd interface {
    // Run 运行命令直到完成。
    Run() error
    // CombinedOutput 运行命令并返回其合并的标准输出和标准错误。遵循 package os/exec 的模式。
    CombinedOutput() ([]byte, error)
    // Output 运行命令并返回标准输出，但不返回标准错误。
    Output() ([]byte, error)
    SetDir(dir string)
    SetStdin(in io.Reader)
    SetStdout(out io.Writer)
    SetStderr(out io.Writer)
    SetEnv(env []string)

    // StdoutPipe 和 StderrPipe 用于获取进程的 Stdout 和 Stderr 作为读取器。
    StdoutPipe() (io.ReadCloser, error)
    StderrPipe() (io.ReadCloser, error)

    // Start 和 Wait 用于非阻塞地运行进程。
    Start() error
    Wait() error

    // Stop 通过发送 SIGTERM 来停止命令。无法保证进程在此函数返回之前停止。如果进程不响应，内部计时器函数将在10秒后发送 SIGKILL 强制终止。
    Stop()
}

// executor 在真正执行 exec() 的情况下实现了 Interface 接口。
type executor struct{}

// New 返回一个新的 Interface，它将使用 os/exec 来运行命令。
func New() Interface {
	return &executor{}
}

// Command 是 Interface 接口的一部分。
func (executor *executor) Command(cmd string, args ...string) Cmd {
	return (*cmdWrapper)(maskErrDotCmd(osexec.Command(cmd, args...)))
}

// CommandContext 是 Interface 接口的一部分。
func (executor *executor) CommandContext(ctx context.Context, cmd string, args ...string) Cmd {
	return (*cmdWrapper)(maskErrDotCmd(osexec.CommandContext(ctx, cmd, args...)))
}

// LookPath 是 Interface 接口的一部分。
func (executor *executor) LookPath(file string) (string, error) {
    path, err := osexec.LookPath(file)
    return path, handleError(maskErrDot(err))
}

// cmdWrapper 包装了 exec.Cmd，以便我们可以捕获错误。
type cmdWrapper osexec.Cmd

var _ Cmd = &cmdWrapper{}

func (cmd *cmdWrapper) SetDir(dir string) {
	cmd.Dir = dir
}

func (cmd *cmdWrapper) SetStdin(in io.Reader) {
	cmd.Stdin = in
}

func (cmd *cmdWrapper) SetStdout(out io.Writer) {
	cmd.Stdout = out
}

func (cmd *cmdWrapper) SetStderr(out io.Writer) {
	cmd.Stderr = out
}

func (cmd *cmdWrapper) SetEnv(env []string) {
	cmd.Env = env
}

func (cmd *cmdWrapper) StdoutPipe() (io.ReadCloser, error) {
    r, err := (*osexec.Cmd)(cmd).StdoutPipe()
    return r, handleError(err)
}

func (cmd *cmdWrapper) StderrPipe() (io.ReadCloser, error) {
    r, err := (*osexec.Cmd)(cmd).StderrPipe()
    return r, handleError(err)
}

func (cmd *cmdWrapper) Start() error {
    err := (*osexec.Cmd)(cmd).Start()
    return handleError(err)
}

func (cmd *cmdWrapper) Wait() error {
    err := (*osexec.Cmd)(cmd).Wait()
    return handleError(err)
}

// Run 是 Cmd 接口的一部分。
func (cmd *cmdWrapper) Run() error {
    err := (*osexec.Cmd)(cmd).Run()
    return handleError(err)
}

// CombinedOutput 是 Cmd 接口的一部分。
func (cmd *cmdWrapper) CombinedOutput() ([]byte, error) {
    out, err := (*osexec.Cmd)(cmd).CombinedOutput()
    return out, handleError(err)
}

func (cmd *cmdWrapper) Output() ([]byte, error) {
    out, err := (*osexec.Cmd)(cmd).Output()
    return out, handleError(err)
}

// Stop 是 Cmd 接口的一部分。
func (cmd *cmdWrapper) Stop() {
    c := (*osexec.Cmd)(cmd)

    if c.Process == nil {
        return
    }

    c.Process.Signal(syscall.SIGTERM)

    time.AfterFunc(10*time.Second, func() {
        if !c.ProcessState.Exited() {
            c.Process.Signal(syscall.SIGKILL)
        }
    })
}

func handleError(err error) error {
    if err == nil {
        return nil
    }

    switch e := err.(type) {
    case *osexec.ExitError:
        return &ExitErrorWrapper{e}
    case *fs.PathError:
        return ErrExecutableNotFound
    case *osexec.Error:
        if e.Err == osexec.ErrNotFound {
            return ErrExecutableNotFound
        }
    }

    return err
}
```

##### handleError

```GO
func handleError(err error) error {
    // 如果 err 为 nil，则返回 nil，表示没有错误。
    if err == nil {
        return nil
    }

    switch e := err.(type) {
    case *osexec.ExitError:
        // 如果 err 类型为 *osexec.ExitError，则返回一个 ExitErrorWrapper，将 err 包装起来。
        return &ExitErrorWrapper{e}
    case *fs.PathError:
        // 如果 err 类型为 *fs.PathError，则返回 ErrExecutableNotFound，表示可执行文件未找到。
        return ErrExecutableNotFound
    case *osexec.Error:
        if e.Err == osexec.ErrNotFound {
            // 如果 err 的内部错误为 osexec.ErrNotFound，则返回 ErrExecutableNotFound，表示可执行文件未找到。
            return ErrExecutableNotFound
        }
    }

    return err
}
```

###### ExitError

```go
// ExitError 是一个接口，提供了与 os.ProcessState 类似的 API，os/exec 中的 ExitError 就是这样的类型。
// 这个接口设计得更易于测试，可能会失去底层库的某些跨平台特性。
type ExitError interface {
    String() string
    Error() string
    Exited() bool
    ExitStatus() int
}
```

###### ExitErrorWrapper&ErrExecutableNotFound

```go
// ExitErrorWrapper 是基于 os/exec.ExitError 实现的 ExitError。
// 注意：标准的 exec.ExitError 是类型 *os.ProcessState，而它已经实现了 Exited()。
type ExitErrorWrapper struct {
	*osexec.ExitError
}

var _ ExitError = &ExitErrorWrapper{}

// ExitStatus 是 ExitError 接口的一部分。
func (eew ExitErrorWrapper) ExitStatus() int {
    ws, ok := eew.Sys().(syscall.WaitStatus)
    if !ok {
    	panic("can't call ExitStatus() on a non-WaitStatus exitErrorWrapper")
    }
    return ws.ExitStatus()
}

// ErrExecutableNotFound 表示未找到可执行文件时返回的错误。
var ErrExecutableNotFound = osexec.ErrNotFound
```

#### getIPTablesVersion

```go
// getIPTablesVersion 运行 "iptables --version" 命令并解析返回的版本信息。
const iptablesVersionPattern = v([0-9]+(\.[0-9]+)+)

func getIPTablesVersion(exec utilexec.Interface, protocol Protocol) (*utilversion.Version, error) {
    // 这里不访问可变状态，因此不需要使用接口/运行器。
    iptablesCmd := iptablesCommand(protocol)
    bytes, err := exec.Command(iptablesCmd, "--version").CombinedOutput()
    if err != nil {
    	return nil, err
    }
    versionMatcher := regexp.MustCompile(iptablesVersionPattern)
    match := versionMatcher.FindStringSubmatch(string(bytes))
    if match == nil {
    	return nil, fmt.Errorf("no iptables version found in string: %s", bytes)
    }
    version, err := utilversion.ParseGeneric(match[1])
    if err != nil {
    	return nil, fmt.Errorf("iptables version %q is not a valid version string: %v", match[1], err)
    }

    return version, nil
}
```

#### iptablesCommand

```go
func iptablesCommand(protocol Protocol) string {
    if protocol == ProtocolIPv6 {
    	return cmdIP6Tables
    }
    return cmdIPTables
}
```

#### getIPTablesWaitFlag

```go
// getIPTablesWaitFlag 检查 iptables 版本是否具有 "wait" 标志。
func getIPTablesWaitFlag(version *utilversion.Version) []string {
    switch {
        case version.AtLeast(WaitIntervalMinVersion):
        	return []string{WaitString, WaitSecondsValue, WaitIntervalString, WaitIntervalUsecondsValue}
        case version.AtLeast(WaitSecondsMinVersion):
        	return []string{WaitString, WaitSecondsValue}
        case version.AtLeast(WaitMinVersion):
        	return []string{WaitString}
        default:
        	return nil
    }
}
```

#### getIPTablesRestoreWaitFlag

```GO
// getIPTablesRestoreWaitFlag 检查 iptables-restore 版本是否具有 "wait" 标志。
func getIPTablesRestoreWaitFlag(version *utilversion.Version, exec utilexec.Interface, protocol Protocol) []string {
    if version.AtLeast(WaitRestoreMinVersion) {
    	return []string{WaitString, WaitSecondsValue, WaitIntervalString, WaitIntervalUsecondsValue}
    }

    // 较旧的版本可能已经反向移植了一些功能；如果 iptables-restore 支持 --version，
    // 假设它也支持 --wait。
    vstring, err := getIPTablesRestoreVersionString(exec, protocol)
    if err != nil || vstring == "" {
        klog.V(3).InfoS("Couldn't get iptables-restore version; assuming it doesn't support --wait")
        return nil
    }
    if _, err := utilversion.ParseGeneric(vstring); err != nil {
        klog.V(3).InfoS("Couldn't parse iptables-restore version; assuming it doesn't support --wait")
        return nil
    }
    return []string{WaitString}
}
```

##### getIPTablesRestoreVersionString

```GO
// getIPTablesRestoreVersionString 运行 "iptables-restore --version" 命令获取版本字符串，
// 格式为 "X.X.X"。
func getIPTablesRestoreVersionString(exec utilexec.Interface, protocol Protocol) (string, error) {
    // 这里不访问可变状态，因此不需要使用接口/运行器。

    // iptables-restore 并不总是有 --version，更糟糕的是，在遇到无法识别的命令时，它不会退出。
    // 通过将 stdin 设置为无内容来解决该问题，这样它会立即退出。
    iptablesRestoreCmd := iptablesRestoreCommand(protocol)
    cmd := exec.Command(iptablesRestoreCmd, "--version")
    cmd.SetStdin(bytes.NewReader([]byte{}))
    bytes, err := cmd.CombinedOutput()
    if err != nil {
        return "", err
    }
    versionMatcher := regexp.MustCompile(iptablesVersionPattern)
    match := versionMatcher.FindStringSubmatch(string(bytes))
    if match == nil {
        return "", fmt.Errorf("no iptables version found in string: %s", bytes)
    }
    return match[1], nil
}
```

### EnsureChain

```GO
// 确保链表存在的函数，属于Interface接口的一部分。
func (runner *runner) EnsureChain(table Table, chain Chain) (bool, error) {
	// 创建完整的参数列表
	fullArgs := makeFullArgs(table, chain)

	// 获取锁
	runner.mu.Lock()
	defer runner.mu.Unlock()

	// 调用runner的run函数执行操作opCreateChain，传入参数fullArgs
	out, err := runner.run(opCreateChain, fullArgs)
	if err != nil {
		// 如果发生错误，并且错误是ExitError类型的
		if ee, ok := err.(utilexec.ExitError); ok {
			// 如果进程已退出且退出状态为1，则表示链表已存在，直接返回true和nil
			if ee.Exited() && ee.ExitStatus() == 1 {
				return true, nil
			}
		}
		// 否则返回false，以及格式化后的错误信息
		return false, fmt.Errorf("error creating chain %q: %v: %s", chain, err, out)
	}
	// 没有发生错误，返回false和nil
	return false, nil
}

```

#### makeFullArgs

```go
// 创建完整的参数列表
func makeFullArgs(table Table, chain Chain, args ...string) []string {
	return append([]string{string(chain), "-t", string(table)}, args...)
}
```

#### run

```go
// 调用runner的run函数执行操作op，传入参数args
func (runner *runner) run(op operation, args []string) ([]byte, error) {
	return runner.runContext(context.TODO(), op, args)
}

// 调用runner的runContext函数执行操作op，传入参数args
func (runner *runner) runContext(ctx context.Context, op operation, args []string) ([]byte, error) {
	// 获取iptables命令
	iptablesCmd := iptablesCommand(runner.protocol)
	// 创建完整的参数列表
	fullArgs := append(runner.waitFlag, string(op))
	fullArgs = append(fullArgs, args...)
	klog.V(5).InfoS("Running", "command", iptablesCmd, "arguments", fullArgs)
	if ctx == nil {
		// 在当前上下文中执行命令并返回输出
		return runner.exec.Command(iptablesCmd, fullArgs...).CombinedOutput()
	}
	// 在指定上下文中执行命令并返回输出
	return runner.exec.CommandContext(ctx, iptablesCmd, fullArgs...).CombinedOutput()
	// 不要在这里记录错误 - 调用者可能不认为这是一个错误。
}
```

### FlushChain

```go
// 清空链表的函数，属于Interface接口的一部分。
func (runner *runner) FlushChain(table Table, chain Chain) error {
	// 创建完整的参数列表
	fullArgs := makeFullArgs(table, chain)

	// 获取锁
	runner.mu.Lock()
	defer runner.mu.Unlock()

	// 调用runner的run函数执行操作opFlushChain，传入参数fullArgs
	out, err := runner.run(opFlushChain, fullArgs)
	if err != nil {
		// 返回格式化后的错误信息
		return fmt.Errorf("error flushing chain %q: %v: %s", chain, err, out)
	}
	// 没有发生错误，返回nil
	return nil
}
```

### DeleteChain

```go
// 删除链表的函数，属于Interface接口的一部分。
func (runner *runner) DeleteChain(table Table, chain Chain) error {
	// 创建完整的参数列表
	fullArgs := makeFullArgs(table, chain)

	// 获取锁
	runner.mu.Lock()
	defer runner.mu.Unlock()

	// 调用runner的run函数执行操作opDeleteChain，传入参数fullArgs
	out, err := runner.run(opDeleteChain, fullArgs)
	if err != nil {
		// 返回格式化后的错误信息
		return fmt.Errorf("error deleting chain %q: %v: %s", chain, err, out)
	}
	// 没有发生错误，返回nil
	return nil
}
```

### DeleteChain

```go
// 删除链表的函数，属于Interface接口的一部分。
func (runner *runner) DeleteChain(table Table, chain Chain) error {
	// 创建完整的参数列表
	fullArgs := makeFullArgs(table, chain)

	// 获取锁
	runner.mu.Lock()
	defer runner.mu.Unlock()

	// 调用runner的run函数执行操作opDeleteChain，传入参数fullArgs
	out, err := runner.run(opDeleteChain, fullArgs)
	if err != nil {
		// 返回格式化后的错误信息
		return fmt.Errorf("error deleting chain %q: %v: %s", chain, err, out)
	}
	// 没有发生错误，返回nil
	return nil
}
```

### EnsureRule

```go
// 确保规则存在的函数，属于Interface接口的一部分。
func (runner *runner) EnsureRule(position RulePosition, table Table, chain Chain, args ...string) (bool, error) {
	// 创建完整的参数列表
	fullArgs := makeFullArgs(table, chain, args...)

	// 获取锁
	runner.mu.Lock()
	defer runner.mu.Unlock()

	// 检查规则是否已存在
	exists, err := runner.checkRule(table, chain, args...)
	if err != nil {
		return false, err
	}
	// 如果规则已存在，则返回true和nil
	if exists {
		return true, nil
	}
	// 规则不存在，则调用runner的run函数执行相应操作，传入参数position和fullArgs
	out, err := runner.run(operation(position), fullArgs)
	if err != nil {
		// 返回格式化后的错误信息
		return false, fmt.Errorf("error appending rule: %v: %s", err, out)
	}
	// 没有发生错误，返回false和nil
	return false, nil
}
```

#### checkRule

```go
// checkRule函数用于检查规则是否存在
// 如果能够检查规则的存在性，则返回(bool, nil)
// 如果检查过程失败，则返回(<undefined>, error)
func (runner *runner) checkRule(table Table, chain Chain, args ...string) (bool, error) {
	if runner.hasCheck {
		// 使用"-C"标志执行规则检查
		return runner.checkRuleUsingCheck(makeFullArgs(table, chain, args...))
	}
	// 否则，执行无检查的规则检查
	return runner.checkRuleWithoutCheck(table, chain, args...)
}
```

##### checkRuleUsingCheck

```go
// 使用"-C"标志执行规则检查
func (runner *runner) checkRuleUsingCheck(args []string) (bool, error) {
	// 设置超时时间为5分钟
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// 调用runner的runContext函数执行操作opCheckRule，传入参数args
	out, err := runner.runContext(ctx, opCheckRule, args)
	if ctx.Err() == context.DeadlineExceeded {
		return false, fmt.Errorf("timed out while checking rules")
	}
	if err == nil {
		return true, nil
	}
	if ee, ok := err.(utilexec.ExitError); ok {
		// iptables使用exit(1)来表示操作失败，与命令行格式错误等不同。
		if ee.Exited() && ee.ExitStatus() == 1 {
			return false, nil
		}
	}
	return false, fmt.Errorf("error checking rule: %v: %s", err, out)
}
```

### DeleteRule

```go
// DeleteRule 是 Interface 接口的一部分。
func (runner *runner) DeleteRule(table Table, chain Chain, args ...string) error {
	fullArgs := makeFullArgs(table, chain, args...) // 根据给定的 table、chain 和 args 创建完整的参数列表

	runner.mu.Lock() // 加锁
	defer runner.mu.Unlock() // 解锁

	exists, err := runner.checkRule(table, chain, args...) // 检查规则是否存在
	if err != nil {
		return err
	}
	if !exists { // 如果规则不存在，则直接返回
		return nil
	}
	out, err := runner.run(opDeleteRule, fullArgs) // 执行删除规则的操作
	if err != nil {
		return fmt.Errorf("error deleting rule: %v: %s", err, out) // 如果出错，则返回带有错误信息的错误
	}
	return nil
}
```

### IsIPv6

```go
func (runner *runner) IsIPv6() bool {
	return runner.protocol == ProtocolIPv6 // 判断是否为 IPv6 协议
}
```

### Protocol

```go
func (runner *runner) Protocol() Protocol {
	return runner.protocol // 返回协议类型
}
```

### SaveInto

```go
// SaveInto 是 Interface 接口的一部分。
func (runner *runner) SaveInto(table Table, buffer *bytes.Buffer) error {
	runner.mu.Lock() // 加锁
	defer runner.mu.Unlock() // 解锁

	trace := utiltrace.New("iptables save") // 创建追踪日志
	defer trace.LogIfLong(2 * time.Second) // 在 2 秒钟后记录日志

	iptablesSaveCmd := iptablesSaveCommand(runner.protocol) // 获取 iptables 保存命令
	args := []string{"-t", string(table)} // 创建参数列表
	klog.V(4).InfoS("Running", "command", iptablesSaveCmd, "arguments", args) // 记录日志

	cmd := runner.exec.Command(iptablesSaveCmd, args...) // 创建命令对象
	cmd.SetStdout(buffer) // 设置标准输出为给定的 buffer
	stderrBuffer := bytes.NewBuffer(nil)
	cmd.SetStderr(stderrBuffer) // 设置标准错误输出为新的缓冲区

	err := cmd.Run() // 运行命令
	if err != nil {
		stderrBuffer.WriteTo(buffer) // 将标准错误输出写入 buffer，忽略错误，因为需要返回原始错误
	}
	return err // 返回错误
}
```

### Restore

```go
// Restore 是 Interface 接口的一部分。
func (runner *runner) Restore(table Table, data []byte, flush FlushFlag, counters RestoreCountersFlag) error {
	args := []string{"-T", string(table)} // 设置参数列表
	return runner.restoreInternal(args, data, flush, counters) // 调用 restoreInternal 方法进行恢复
}
```

#### restoreInternal

```go
// restoreInternal 是 Restore 和 RestoreAll 的共享部分
func (runner *runner) restoreInternal(args []string, data []byte, flush FlushFlag, counters RestoreCountersFlag) error {
	runner.mu.Lock() // 加锁
	defer runner.mu.Unlock() // 解锁

	trace := utiltrace.New("iptables restore") // 创建追踪日志
	defer trace.LogIfLong(2 * time.Second) // 在 2 秒钟后记录日志

	if !flush { // 如果不需要清空规则，则在参数列表中添加 --noflush 标志
		args = append(args, "--noflush")
	}
	if counters { // 如果需要恢复计数器，则在参数列表中添加 --counters 标志
		args = append(args, "--counters")
	}

	if len(runner.restoreWaitFlag) == 0 { // 如果没有设置 restoreWaitFlag，则需要获取 iptables 锁
		locker, err := grabIptablesLocks(runner.lockfilePath14x, runner.lockfilePath16x) // 获取 iptables 锁
		if err != nil {
			return err
		}
		trace.Step("Locks grabbed") // 记录日志
		defer func(locker iptablesLocker) { // 在函数返回前关闭锁
			if err := locker.Close(); err != nil {
				klog.ErrorS(err, "Failed to close iptables locks") // 如果关闭锁时发生错误，则记录日志
			}
		}(locker)
	}

	fullArgs := append(runner.restoreWaitFlag, args...) // 创建完整的参数列表
	iptablesRestoreCmd := iptablesRestoreCommand(runner.protocol) // 获取 iptables 恢复命令
	klog.V(4).InfoS("Running", "command", iptablesRestoreCmd, "arguments", fullArgs) // 记录日志

	cmd := runner.exec.Command(iptablesRestoreCmd, fullArgs...) // 创建命令对象
	cmd.SetStdin(bytes.NewBuffer(data)) // 设置标准输入为给定的数据
	b, err := cmd.CombinedOutput() // 运行命令并返回输出
	if err != nil {
		pErr, ok := parseRestoreError(string(b)) // 解析错误信息
		if ok {
			return pErr
		}
		return fmt.Errorf("%w: %s", err, b) // 返回带有错误信息的错误
	}
	return nil // 返回 nil 表示没有错误发生
}
```

##### grabIptablesLocks

```go
func grabIptablesLocks(lockfilePath14x, lockfilePath16x string) (iptablesLocker, error) {
	var err error
	var success bool

	l := &locker{} // 创建 locker 对象
	defer func(l *locker) {
		if !success { // 如果不成功，则立即清理资源
			l.Close()
		}
	}(l)

	l.lock16, err = os.OpenFile(lockfilePath16x, os.O_CREATE, 0600) // 打开 1.6.x 样式的锁
	if err != nil {
		return nil, fmt.Errorf("failed to open iptables lock %s: %v", lockfilePath16x, err)
	}

	if err := wait.PollImmediate(200*time.Millisecond, 2*time.Second, func() (bool, error) {
		if err := grabIptablesFileLock(l.lock16); err != nil { // 获取文件锁
			return false, nil
		}
		return true, nil
	}); err != nil {
		return nil, fmt.Errorf("failed to acquire new iptables lock: %v", err)
	}

	if err := wait.PollImmediate(200*time.Millisecond, 2*time.Second, func() (bool, error) {
		l.lock14, err = net.ListenUnix("unix", &net.UnixAddr{Name: lockfilePath14x, Net: "unix"}) // 监听 1.4.x 样式的锁
		if err != nil {
			return false, nil
		}
		return true, nil
	}); err != nil {
		return nil, fmt.Errorf("failed to acquire old iptables lock: %v", err)
	}

	success = true
	return l, nil // 返回 locker 对象和错误
}
```

###### parseRestoreError

```go
// parseRestoreError 提取错误信息中的行号，并返回 parseError 结构体和是否成功的标志
func parseRestoreError(str string) (ParseError, bool) {
	errors := strings.Split(str, ":")
	if len(errors) != 2 {
		return nil, false
	}
	cmd := errors[0]
	matches := regexpParseError.FindStringSubmatch(errors[1]) // 使用正则表达式匹配行号
	if len(matches) != 2 {
		return nil, false
	}
	line, errMsg := strconv.Atoi(matches[1])
	if errMsg != nil {
		return nil, false
	}
	return parseError{cmd: cmd, line: line}, true // 返回 parseError 结构体和成功标志
}
```

###### parseError

```go
type parseError struct {
	cmd  string
	line int
}

func (e parseError) Line() int {
	return e.line // 返回行号
}

func (e parseError) Error() string {
	return fmt.Sprintf("%s: input error on line %d: ", e.cmd, e.line) // 返回错误信息字符串
}
```

### RestoreAll

```go
// RestoreAll 是 Interface 接口的一部分。
func (runner *runner) RestoreAll(data []byte, flush FlushFlag, counters RestoreCountersFlag) error {
	args := make([]string, 0) // 创建空的参数列表
	return runner.restoreInternal(args, data, flush, counters) // 调用 restoreInternal 方法进行恢复
}
```

### Monitor

```go
// Monitor is part of Interface
// 监视器函数，实现了Interface接口的一部分
func (runner *runner) Monitor(canary Chain, tables []Table, reloadFunc func(), interval time.Duration, stopCh <-chan struct{}) {
	// 进入无限循环，用于持续监视iptables状态
	for {
		// 使用utilwait包的PollImmediateUntil函数，每隔一定时间执行一次回调函数，直到回调函数返回true或者stopCh被关闭
		_ = utilwait.PollImmediateUntil(interval, func() (bool, error) {
			// 遍历所有的tables，确保每个table中的canary链存在
			for _, table := range tables {
				if _, err := runner.EnsureChain(table, canary); err != nil {
					// 如果设置canary链失败，记录错误日志并返回false
					klog.ErrorS(err, "Could not set up iptables canary", "table", table, "chain", canary)
					return false, nil
				}
			}
			// 所有canary链都设置成功，返回true
			return true, nil
		}, stopCh)

		// 使用utilwait包的PollUntil函数，每隔一定时间执行一次回调函数，直到回调函数返回true或者stopCh被关闭
		err := utilwait.PollUntil(interval, func() (bool, error) {
			// 检查tables[0]中的canary链是否存在
			if exists, err := runner.ChainExists(tables[0], canary); exists {
				return false, nil
			} else if isResourceError(err) {
				// 如果发生资源错误，记录错误日志并返回false
				klog.ErrorS(err, "Could not check for iptables canary", "table", tables[0], "chain", canary)
				return false, nil
			}
			// canary链已被删除，记录日志
			klog.V(2).InfoS("IPTables canary deleted", "table", tables[0], "chain", canary)
			
			// 使用utilwait包的PollImmediate函数，每隔一定时间执行一次回调函数，直到回调函数返回true或者超时
			err := utilwait.PollImmediate(iptablesFlushPollTime, iptablesFlushTimeout, func() (bool, error) {
				// 遍历除了tables[0]之外的其他tables中的canary链，检查它们是否存在
				for i := 1; i < len(tables); i++ {
					if exists, err := runner.ChainExists(tables[i], canary); exists || isResourceError(err) {
						return false, nil
					}
				}
				// 所有其他tables中的canary链都不存在，返回true
				return true, nil
			})
			if err != nil {
				// 检测到iptables状态不一致，记录日志
				klog.InfoS("Inconsistent iptables state detected")
			}
			// 返回true，表示iptables状态已恢复正常
			return true, nil
		}, stopCh)

		if err != nil {
			// stopCh被关闭，执行清理操作并返回
			for _, table := range tables {
				_ = runner.DeleteChain(table, canary)
			}
			return
		}

		// iptables状态已恢复正常，执行重新加载操作
		klog.V(2).InfoS("Reloading after iptables flush")
		reloadFunc()
	}
}
```

### ChainExists

```go
// ChainExists函数，实现了Interface接口的一部分
func (runner *runner) ChainExists(table Table, chain Chain) (bool, error) {
	// 构造完整的参数
	fullArgs := makeFullArgs(table, chain)

	// 获取锁
	runner.mu.Lock()
	defer runner.mu.Unlock()

	// 使用utiltrace包创建一个跟踪器
	trace := utiltrace.New("iptables ChainExists")
	defer trace.LogIfLong(2 * time.Second)

	// 调用runner的run方法执行iptables的ListChain命令，并检查返回结果
	_, err := runner.run(opListChain, fullArgs)
	return err == nil, err
}
```

### Present

```go
// Present函数用于检测当前内核是否支持iptables，通过检查默认表和链的存在来判断
func (runner *runner) Present() bool {
	// 检查TableNAT和ChainPostrouting是否存在
	if _, err := runner.ChainExists(TableNAT, ChainPostrouting); err != nil {
		return false
	}

	return true
}
```





## Proxier

```go
// Proxier是基于iptables的代理，用于在本地主机（localhost:lport）和提供实际后端服务的服务之间进行连接。
type Proxier struct {
	endpointsChanges *proxy.EndpointChangeTracker // endpointsChanges用于跟踪endpoints的变化
	serviceChanges   *proxy.ServiceChangeTracker  // serviceChanges用于跟踪services的变化

	mu           sync.Mutex        // 保护以下字段的互斥锁
	svcPortMap   proxy.ServicePortMap    // 服务端口映射表
	endpointsMap proxy.EndpointsMap      // Endpoints映射表
	nodeLabels   map[string]string     // 节点标签映射表
	// endpointSlicesSynced和servicesSynced在启动后同步相应对象后设置为true。
	// 这用于避免在kube-proxy重启后使用一些部分数据更新iptables。
	endpointSlicesSynced bool    // EndpointSlice同步标志
	servicesSynced       bool    // Service同步标志
	needFullSync         bool    // 需要进行完全同步的标志
	initialized          int32   // 初始化标志，用于同步初始化过程
	syncRunner           *async.BoundedFrequencyRunner    // 控制对syncProxyRules的调用频率
	syncPeriod           time.Duration    // 同步周期
	lastIPTablesCleanup  time.Time    // 上次清理iptables的时间

	// 以下字段在实际运行中相当于常量，无需互斥锁。
	iptables       utiliptables.Interface    // iptables接口
	masqueradeAll  bool    // 是否对所有流量进行masquerade
	masqueradeMark string    // masquerade规则的标记
	exec           utilexec.Interface    // 执行命令的接口
	localDetector  proxyutiliptables.LocalTrafficDetector    // 本地流量检测器
	hostname       string    // 主机名
	nodeIP         net.IP    // 节点IP地址
	recorder       events.EventRecorder    // 事件记录器

	serviceHealthServer healthcheck.ServiceHealthServer    // 服务健康检查服务器
	healthzServer       healthcheck.ProxierHealthUpdater    // 健康检查服务器

	precomputedProbabilities []string    // 预计算的概率字符串缓存

	// 以下缓冲区用于重用内存并避免对性能产生显著影响的分配。
	iptablesData             *bytes.Buffer    // iptables数据缓冲区
	existingFilterChainsData *bytes.Buffer    // 现有过滤链数据缓冲区
	filterChains             utilproxy.LineBuffer    // 过滤链缓冲区
	filterRules              utilproxy.LineBuffer    // 过滤规则缓冲区
	natChains                utilproxy.LineBuffer    // NAT链缓冲区
	natRules                 utilproxy.LineBuffer    // NAT规则缓冲区

	largeClusterMode bool    // 是否处于大集群模式

	localhostNodePorts bool    // 是否允许通过localhost访问NodePort服务
	nodePortAddresses *utilproxy.NodePortAddresses    // NodePort工作的网络接口
	networkInterfacer utilproxy.NetworkInterfacer    // 网络接口
}

// Proxier实现了proxy.Provider接口
var _ proxy.Provider = &Proxier{}
```

### NewProxier

```go
// NewProxier根据iptables Interface实例返回一个新的Proxier。
// 由于iptables的逻辑，假定在机器上只有一个活动的Proxier。
// 如果iptables在更新或获取初始锁时失败，将返回错误。
// 创建proxier后，它将在后台保持iptables的最新状态，并且如果某个iptables调用失败，不会终止。
func NewProxier(ipFamily v1.IPFamily,
	ipt utiliptables.Interface,
	sysctl utilsysctl.Interface,
	exec utilexec.Interface,
	syncPeriod time.Duration,
	minSyncPeriod time.Duration,
	masqueradeAll bool,
	localhostNodePorts bool,
	masqueradeBit int,
	localDetector proxyutiliptables.LocalTrafficDetector,
	hostname string,
	nodeIP net.IP,
	recorder events.EventRecorder,
	healthzServer healthcheck.ProxierHealthUpdater,
	nodePortAddressStrings []string,
) (*Proxier, error) {
	nodePortAddresses := utilproxy.NewNodePortAddresses(ipFamily, nodePortAddressStrings)

	if !nodePortAddresses.ContainsIPv4Loopback() {
		localhostNodePorts = false
	}
	if localhostNodePorts {
		// 设置route_localnet sysctl，以允许在localhost上公开NodePort
		// 参考https://issues.k8s.io/90259
		klog.InfoS("Setting route_localnet=1 to allow node-ports on localhost; to change this either disable iptables.localhostNodePorts (--iptables-localhost-nodeports) or set nodePortAddresses (--nodeport-addresses) to filter loopback addresses")
		if err := utilproxy.EnsureSysctl(sysctl, sysctlRouteLocalnet, 1); err != nil {
			return nil, err
		}
	}

	// 当容器连接到Linux桥时（但不适用于SDN桥），代理需要br_netfilter和bridge-nf-call-iptables=1。
	// 直到大多数插件处理此问题，当配置缺失时记录日志。
	if val, err := sysctl.GetSysctl(sysctlBridgeCallIPTables); err == nil && val != 1 {
		klog.InfoS("Missing br-netfilter module or unset sysctl br-nf-call-iptables, proxy may not work as intended")
	}

	// 生成用于SNAT规则的masquerade标记。
	masqueradeValue := 1 << uint(masqueradeBit)
	masqueradeMark := fmt.Sprintf("%#08x", masqueradeValue)
	klog.V(2).InfoS("Using iptables mark for masquerade", "ipFamily", ipt.Protocol(), "mark", masqueradeMark)

	serviceHealthServer := healthcheck.NewServiceHealthServer(hostname, recorder, nodePortAddresses, healthzServer)

	proxier := &Proxier{
		svcPortMap:               make(proxy.ServicePortMap),
		serviceChanges:           proxy.NewServiceChangeTracker(newServiceInfo, ipFamily, recorder, nil),
		endpointsMap:             make(proxy.EndpointsMap),
		endpointsChanges:         proxy.NewEndpointChangeTracker(hostname, newEndpointInfo, ipFamily, recorder, nil),
		needFullSync:             true,
		syncPeriod:               syncPeriod,
		iptables:                 ipt,
		masqueradeAll:            masqueradeAll,
		masqueradeMark:           masqueradeMark,
		exec:                     exec,
		localDetector:            localDetector,
		hostname:                 hostname,
		nodeIP:                   nodeIP,
		recorder:                 recorder,
		serviceHealthServer:      serviceHealthServer,
		healthzServer:            healthzServer,
		precomputedProbabilities: make([]string, 0, 1001),
		iptablesData:             bytes.NewBuffer(nil),
		existingFilterChainsData: bytes.NewBuffer(nil),
		filterChains:             utilproxy.LineBuffer{},
		filterRules:              utilproxy.LineBuffer{},
		natChains:                utilproxy.LineBuffer{},
		natRules:                 utilproxy.LineBuffer{},
		localhostNodePorts:       localhostNodePorts,
		nodePortAddresses:        nodePortAddresses,
		networkInterfacer:        utilproxy.RealNetwork{},
	}

	burstSyncs := 2
	klog.V(2).InfoS("Iptables sync params", "ipFamily", ipt.Protocol(), "minSyncPeriod", minSyncPeriod, "syncPeriod", syncPeriod, "burstSyncs", burstSyncs)
	// 我们将syncPeriod传递给ipt.Monitor，只有在需要时才会调用我们。
	// 无论如何，我们仍然需要传递*某个*maxInterval给NewBoundedFrequencyRunner。
	// time.Hour是任意的。
	proxier.syncRunner = async.NewBoundedFrequencyRunner("sync-runner", proxier.syncProxyRules, minSyncPeriod, time.Hour, burstSyncs)

	go ipt.Monitor(kubeProxyCanaryChain, []utiliptables.Table{utiliptables.TableMangle, utiliptables.TableNAT, utiliptables.TableFilter},
		proxier.forceSyncProxyRules, syncPeriod, wait.NeverStop)

	if ipt.HasRandomFully() {
		klog.V(2).InfoS("Iptables supports --random-fully", "ipFamily", ipt.Protocol())
	} else {
		klog.V(2).InfoS("Iptables does not support --random-fully", "ipFamily", ipt.Protocol())
	}

	return proxier, nil
}
```

### NewDualStackProxier

```go
// NewDualStackProxier创建一个MetaProxier实例，包含IPv4和IPv6代理。
func NewDualStackProxier(
	ipt [2]utiliptables.Interface,
	sysctl utilsysctl.Interface,
	exec utilexec.Interface,
	syncPeriod time.Duration,
	minSyncPeriod time.Duration,
	masqueradeAll bool,
	localhostNodePorts bool,
	masqueradeBit int,
	localDetectors [2]proxyutiliptables.LocalTrafficDetector,
	hostname string,
	nodeIP [2]net.IP,
	recorder events.EventRecorder,
	healthzServer healthcheck.ProxierHealthUpdater,
	nodePortAddresses []string,
) (proxy.Provider, error) {
	// 创建单栈proxier的ipv4实例
	ipv4Proxier, err := NewProxier(v1.IPv4Protocol, ipt[0], sysctl,
		exec, syncPeriod, minSyncPeriod, masqueradeAll, localhostNodePorts, masqueradeBit, localDetectors[0], hostname,
		nodeIP[0], recorder, healthzServer, nodePortAddresses)
	if err != nil {
		return nil, err
	}
	// 创建单栈proxier的ipv6实例
	ipv6Proxier, err := NewProxier(v1.IPv6Protocol, ipt[1], sysctl,
		exec, syncPeriod, minSyncPeriod, masqueradeAll, localhostNodePorts, masqueradeBit, localDetectors[1], hostname,
		nodeIP[1], recorder, healthzServer, nodePortAddresses)
	if err != nil {
		return nil, err
	}

	proxier := &proxy.MetaProxier{
		IPv4Proxier: ipv4Proxier,
		IPv6Proxier: ipv6Proxier,
	}

	return proxier, nil
}
```

