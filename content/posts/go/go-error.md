---
title: "Go错误处理"
date: 2022-01-22T15:40:42+08:00
draft: false
toc: true
categories: [go]
tags: [golang]
authors:
    - haiyux
featuredImagePreview: /img/go.webp
---

## error定义

### 数据结构

go语言error是一普通的值，实现方式为简单一个接口。

```go
// The error built-in interface type is the conventional interface for
// representing an error condition, with the nil value representing no error.
type error interface {
    Error() string
}
```

创建error

1. 使用`errors.New()`

```go
// New returns an error that formats as the given text.
// Each call to New returns a distinct error value even if the text is identical.
func New(text string) error {
    return &errorString{text}
}

// errorString is a trivial implementation of error.
type errorString struct {
    s string
}

func (e *errorString) Error() string {
    return e.s
}
```

返回的是errorString结构体 实现了error接口的Error()方法

2. 使用`fmt.Errorf（）`创建

创建方式为把字符串拼接起来，然后调用errors.New().

### 基础库中的自定义的error

bufio中的错误：

```go
ErrTooLong         = errors.New("bufio.Scanner: token too long")
ErrNegativeAdvance = errors.New("bufio.Scanner: SplitFunc returns negative advance count")
ErrAdvanceTooFar   = errors.New("bufio.Scanner: SplitFunc returns advance count beyond input")
ErrBadReadCount    = errors.New("bufio.Scanner: Read returned impossible count")
```

## error的比较

```go
package main

import (
    "errors"
    "fmt"
)

type errorString struct {
    s string
}

func new(s string) error {
    return &errorString{s: s}
}

func (e *errorString) Error() string {
    return e.s
}

func main() {
    error1 := errors.New("test")
    error2 := new("test")
    fmt.Println(error1 == error2) // false
}

```

```go
// 比较结构体
package main

import (
    "fmt"
)

type errorString struct {
    s string
}

func new(s string) error {
    return &errorString{s: s}
}

func (e *errorString) Error() string {
    return e.s
}

func main() {
    error1 := new("test")
    fmt.Println(error1 == new("test")) // false
}
```

```go
package main

import (
    "fmt"
)

type errorString struct {
    s string
}

func new(s string) error {
    return errorString{s: s}
}

func (e errorString) Error() string {
    return e.s
}

func main() {
    error1 := new("test")
    fmt.Println(error1 == new("test")) // true
}
```

**error对比为对比对比实现interface的结构体类型 和结构体本身**

## Error or Exception

### 处理错误的演进

1. C

- 单返回值，一般通过传递指针作为入参，返回值为 int 表示成功还是失败。

2. C++

- 引入了 exception，但是无法知道被调用方会抛出什么异常。

3. Java

- 引入了 checked exception，方法的所有者必须申明，调用者必须处理。在启动时抛出大量的异常是司空见惯的事情，并在它们的调用堆栈中尽职地记录下来。Java 异常不再是异常，而是变得司空见惯了。它们从良性到灾难性都有使用，异常的严重性由函数的调用者来区分

4. go

- Go 的处理异常逻辑是不引入 exception，支持多参数返回，所以你很容易的在函数签名中带上实现了 error interface 的对象，交由调用者来判定。

- 如果一个函数返回了 value, error，你不能对这个 value 做任何假设，必须先判定 error。唯一可以忽略 error 的是，如果你连 value 也不关心。

- Go 中有 panic 的机制，如果你认为和其他语言的 exception 一样，那你就错了。当我们抛出异常的时候，相当于你把 exception 扔给了调用者来处理。比如，你在 C++ 中，把 string 转为 int，如果转换失败，会抛出异常。或者在 java 中转换 string 为 date 失败时，会抛出异常。

- Go panic 意味着 fatal error(就是挂了)。不能假设调用者来解决 panic，意味着代码不能继续运行。

- 使用多个返回值和一个简单的约定，Go 解决了让程序员知道什么时候出了问题，并为真正的异常情况保留了 panic。

### 代码对比

```go
package main

import "fmt"

func Positive(x int) bool {
    return x >= 0
}

func Check(x int) {
    if Positive(x) {
        fmt.Println("正数")
    } else {
        fmt.Println("负数")
    }
}

func main() {
    Check(-1) // 负数
    Check(0)  // 正数 bug
    Check(1)  // 正数
}
```

```go
package main

import "fmt"

func Positive(x int) (bool, bool) {
    if x == 0 {
        return false, false
    }
    return x >= 0, true
}

func Check(x int) {
    t, ok := Positive(x)
    if !ok {
        fmt.Println("零")
        return
    }

    if t {
        fmt.Println("正数")
    } else {
        fmt.Println("负数")
    }

}

func main() {
    Check(-1) // 负数
    Check(0)  // 零
    Check(1)  // 正数
}
```

```go
package main

import (
    "errors"
    "fmt"
)

func Positive(x int) (bool, error) {
    if x == 0 {
        return false, errors.New("为零")
    }
    return x >= 0, nil
}

func Check(x int) {
    t, err := Positive(x)
    if err != nil {
        fmt.Println(err)
        return
    }

    if t {
        fmt.Println("正数")
    } else {
        fmt.Println("负数")
    }

}

func main() {
    Check(-1) // 负数
    Check(0)  // 为零
    Check(1)  // 正数
}
```

### error使用

对于真正意外的情况，那些表示不可恢复的程序错误，例如索引越界、不可恢复的环境问题、栈溢出，我们才使用 panic。对于其他的错误情况，我们应该是期望使用 error 来进行判定。

- 简单。

- 考虑失败，而不是成功。

- 没有隐藏的控制流。

- 完全交给你来控制 error。

- Error are values。

## Sentinel Error

预定义的特定错误，我们叫为 sentinel error，这个名字来源于计算机编程中使用一个特定值来表示不可能进行进一步处理的做法。所以对于 Go，我们使用特定的值来表示错误。

```go
if err == ErrSomething { … }
```

类似的 `io.EOF`，更底层的 `syscall.ENOENT`。

使用 sentinel 值是最不灵活的错误处理策略，因为调用方必须使用 == 将结果与预先声明的值进行比较。当您想要提供更多的上下文时，这就出现了一个问题，因为返回一个不同的错误将破坏相等性检查。

甚至是一些有意义的 fmt.Errorf 携带一些上下文，也会破坏调用者的 == ，调用者将被迫查看 error.Error() 方法的输出，以查看它是否与特定的字符串匹配。

- 不依赖检查 error.Error 的输出。

不应该依赖检测 error.Error 的输出，Error 方法存在于 error 接口主要用于方便程序员使用，但不是程序(编写测试可能会依赖这个返回)。这个输出的字符串用于记录日志、输出到 stdout 等。

- Sentinel errors 成为你 API 公共部分。

如果您的公共函数或方法返回一个特定值的错误，那么该值必须是公共的，当然要有文档记录，这会增加 API 的表面积。

如果 API 定义了一个返回特定错误的 interface，则该接口的所有实现都将被限制为仅返回该错误，即使它们可以提供更具描述性的错误。

比如 io.Reader。像 io.Copy 这类函数需要 reader 的实现者比如返回 io.EOF 来告诉调用者没有更多数据了，但这又不是错误。

- Sentinel errors 在两个包之间创建了依赖。

sentinel errors 最糟糕的问题是它们在两个包之间创建了源代码依赖关系。例如，检查错误是否等于 io.EOF，您的代码必须导入 io 包。这个特定的例子听起来并不那么糟糕，因为它非常常见，但是想象一下，当项目中的许多包导出错误值时，存在耦合，项目中的其他包必须导入这些错误值才能检查特定的错误条件(in the form of an import loop)。

- 结论: 尽可能避免 sentinel errors。

我的建议是避免在编写的代码中使用 sentinel errors。在标准库中有一些使用它们的情况，但这不是一个您应该模仿的模式。

## 错误类型

Error type 是实现了 error 接口的自定义类型。例如 MyError 类型记录了文件和行号以展示发生了什么。

```go
type Myerror struct {
    line int
    file string
    s    string
}

func (e *Myerror) Error() string {
    return e.s
}

func new(file string, line int, s string) error {
    return &Myerror{line: line, file: file, s: s}
}
```

因为 MyError 是一个 type，调用者可以使用断言转换成这个类型，来获取更多的上下文信息。

```go
err := new("main.go", 23, "test error")
switch err := err.(type) {
case nil:
    fmt.Println("err is nil")
case *Myerror:
    fmt.Println("type is *Myerror err line :", err.line)
default:
    fmt.Println("None of them")
}

// 结果:type is *Myerror err line : 23
```

与错误值相比，错误类型的一大改进是它们能够包装底层错误以提供更多上下文。

一个不错的例子就是 os.PathError 他提供了底层执行了什么操作、那个路径出了什么问题。

调用者要使用类型断言和类型 switch，就要让自定义的 error 变为 public。这种模型会导致和调用者产生强耦合，从而导致 API 变得脆弱。

结论是尽量避免使用 error types，虽然错误类型比 sentinel errors 更好，因为它们可以捕获关于出错的更多上下文，但是 error types 共享 error values 许多相同的问题。

因此，我的建议是避免错误类型，或者至少避免将它们作为公共 API 的一部分。

### 非透明的error

在我看来，这是最灵活的错误处理策略，因为它要求代码和调用者之间的耦合最少。

我将这种风格称为不透明错误处理，因为虽然您知道发生了错误，但您没有能力看到错误的内部。作为调用者，关于操作的结果，您所知道的就是它起作用了，或者没有起作用(成功还是失败)。

这就是不透明错误处理的全部功能–只需返回错误而不假设其内容

```go
package main

import "os"

func test() error {
    f, err := os.Open("filename.txt")
    if err != nil {
        return err
    }
    // use f 
}
```

为行为而不是类型断言错误  在少数情况下，这种二分错误处理方法是不够的。例如，与进程外的世界进行交互(如网络活动)，需要调用方调查错误的性质，以确定重试该操作是否合理。在这种情况下，我们可以断言错误实现了特定的行为，而不是断言错误是特定的类型或值。考虑这个例子：

```go
// 封装内部
type temporary interface {
    Temporary() bool
}

func IsTemporary(err error) bool {
    te, ok := err.(temporary)
    return ok && te.Temporary()
}

// net包的error
type Error interface {
    error
    Timeout() bool   // Is the error a timeout?
    Temporary() bool // Is the error temporary?
}

// 错误处理
if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
    // 处理
    return
}

if err != nil {

}
```

## Handling Error

无错误的正常流程代码，将成为一条直线，而不是缩进的代码。

```go
f,err  := os.Open("file")
if err != nil {
    // 处理错误
    return
}

// 逻辑
f,err  = os.Open("file2")
if err != nil {
    // 处理错误
    return
}

// 逻辑
```

通过消除错误消除错误处理

```go
// 改进前
func AutoRusquest() (err error) {
  err = Anto()
  if err != nil {
    return
  }  
  return
}

// 改进后
func AutoRusquest() (err error) {
    return Anto()
}

func main() {
    err := AutoRusquest()
    if err != nil {
        // log 
    }
}

// 统计行数
func Countlines(r io.Reader) (int, error) {
    var (
        br    = bufio.NewReader(r)
        lines int
        err   error
    )

    for {
        _, err = br.ReadString('\n')
        lines++
        if err != nil {
            break
        }
    }

    if err != io.EOF {
        return 0, err
    }
    return lines, nil
}



// 改进后
func Countlines(r io.Reader) (int, error) {
    sr := bufio.NewScanner(r)
    lines := 0
    for sr.Scan() {
        lines ++
    }
    return lines,sr.Err()
}
```

## Wrap errors

### 传统error的问题

还记得之前我们 auth 的代码吧，如果 Auto 返回错误，则 Aut0Request 会将错误返回给调用方，调用者可能也会这样做，依此类推。在程序的顶部，程序的主体将把错误打印到屏幕或日志文件中，打印出来的只是：没有这样的文件或目录。

没有生成错误的 file:line 信息。没有导致错误的调用堆栈的堆栈跟踪。这段代码的作者将被迫进行长时间的代码分割，以发现是哪个代码路径触发了文件未找到错误。

```go
func AutoRusquest() (err error) {
  err = Anto()
  if err != nil {
    err = fmt.Errorf("auto failed:%v",err)
    return
  }  
  return
}
```

但是正如我们前面看到的，这种模式与 sentinel errors 或 type assertions 的使用不兼容，因为将错误值转换为字符串，将其与另一个字符串合并，然后将其转换回 fmt.Errorf 破坏了原始错误，导致等值判定失败。

你应该只处理一次错误。处理错误意味着检查错误值，并做出单个决策。

```go
func WriteAll(w io.Writer, buf []byte) {
    w.Write(buf)
}
```

我们经常发现类似的代码，在错误处理中，带了两个任务: 记录日志并且再次返回错误。

```go
func WriteAll(w io.Writer, buf []byte) error {
    _, err := w.Write(buf)
    if err != nil {
        log.Panicln("write buf failed:", err)
        return err
    }
    return nil
}
```

在这个例子中，如果在 w.Write 过程中发生了一个错误，那么一行代码将被写入日志文件中，记录错误发生的文件和行，并且错误也会返回给调用者，调用者可能会记录并返回它，一直返回到程序的顶部。

```go
func WriteConfig(w *io.Writer,config *Config) {
  buf, err := json.Marshal(conf)
  if err != nil {
    log.Printf("could not marshal config: %V", err)
    return err
  }

  if err := Writeall(w, buf); err != nil {
    log.Printf("could not write config: %v", err)
    return err
  }
}

func main() {
    err := Writeconfig(f, &conf)
    fmt.Println(err)
}
/*
unable to write: io.EOF
could not write config: io.EOF
*/
```

Go 中的错误处理契约规定，在出现错误的情况下，不能对其他返回值的内容做出任何假设。由于 JSON 序列化失败，buf 的内容是未知的，可能它不包含任何内容，但更糟糕的是，它可能包含一个半写的 JSON 片段。

由于程序员在检查并记录错误后忘记 return，损坏的缓冲区将被传递给 WriteAll，这可能会成功，因此配置文件将被错误地写入。但是，该函数返回的结果是正确的。

### 栈处理错误

日志记录与错误无关且对调试没有帮助的信息应被视为噪音，应予以质疑。记录的原因是因为某些东西失败了，而日志包含了答案。

- 错误要被日志记录。

- 应用程序处理错误，保证100%完整性。

- 之后不再报告当前错误。

包:github.com/pkg/errors

```go
func main() {
    _, err := Readconfig()
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}

func Readfile(path string) ([]byte, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, errors.Wrap(err, "open failed")
    }

    defer f.Close()
    buf, err := ioutil.ReadAll(f)
    if err != nil {
        return nil, errors.Wrap(err, "read failed")
    }

    return buf, nil
}

func Readconfig() ([]byte, error) {
    home := os.Getenv("HOME")
    config, err := Readfile(filepath.Join(home, "settings.xml"))
    return config, errors.WithMessage(err, "could not read config")
}

/*
could not read config: open failed: open /Users/zhaohaiyu/settings.xml: no such file or directory
exit status 1
*/
func main() {
    _, err := Readconfig()
    if err != nil {
        fmt.Printf("original error: %T -> %v\n", errors.Cause(err), errors.Cause(err))
        fmt.Printf("stack trace: \n%+v\n", err)
        os.Exit(1)
    }
}

/*
original error: *os.PathError -> open /Users/zhaohaiyu/settings.xml: no such file or directory
stack trace: 
open /Users/zhaohaiyu/settings.xml: no such file or directory
open failed
main.Readfile
        /Users/zhaohaiyu/code/test/main.go:35
main.Readconfig
        /Users/zhaohaiyu/code/test/main.go:51
main.main
        /Users/zhaohaiyu/code/test/main.go:22
runtime.main
        /usr/local/Cellar/go/1.15.3/libexec/src/runtime/proc.go:204
runtime.goexit
        /usr/local/Cellar/go/1.15.3/libexec/src/runtime/asm_amd64.s:1374
could not read config
exit status 1
*/
```

通过使用 pkg/errors 包，您可以向错误值添加上下文，这种方式既可以由人也可以由机器检查。

```go
errors.Wrap(err, "read failed")
```

### wrap errors使用

1. 在你的应用代码中，使用 errors.New 或者 errros.Errorf 返回错误。

```go
func parseargs(args []string) error {
    if len(args) < 3 {
        return errors.Errorf("not enough arguments, expected at Least")
    }

    // ...

    return nil
}
```

2. 如果调用其他的函数，通常简单的直接返回。

```go
if err != nil {
  return err
}
```

3. 如果和其他库进行协作，考虑使用 errors.Wrap 或者 errors.Wrapf 保存堆栈信息。同样适用于和标准库协作的时候。

```go
f, err := os.Open(file)
if err != nil {
    return errors.Wrapf(err, "open %s failed",file)
}
```

4. 直接返回错误，而不是每个错误产生的地方到处打日志。

5. 在程序的顶部或者是工作的 goroutine 顶部(请求入口)，使用 %+v 把堆栈详情记录。

```go
func main() {
    err := app.Run()
    if err != nil {
        fmt.Printf("FATAL:%+v\n", err)
        os.Exit(1)
    }
}
```

6. 使用 errors.Cause 获取 root error，再进行和 sentinel error 判定。

### 总结:

- Packages that are reusable across many projects only return root error values.（选择 wrap error 是只有 applications 可以选择应用的策略。具有最高可重用性的包只能返回根错误值。此机制与 Go 标准库中使用的相同(kit 库的 sql.ErrNoRows)。）

- If the error is not going to be handled, wrap and return up the call stack.（这是关于函数/方法调用返回的每个错误的基本问题。如果函数/方法不打算处理错误，那么用足够的上下文 wrap errors 并将其返回到调用堆栈中。例如，额外的上下文可以是使用的输入参数或失败的查询语句。确定您记录的上下文是足够多还是太多的一个好方法是检查日志并验证它们在开发期间是否为您工作。）

- Once an error is handled, it is not allowed to be passed up the call stack any longer.（ 一旦确定函数/方法将处理错误，错误就不再是错误。如果函数/方法仍然需要发出返回，则它不能返回错误值。它应该只返回零(比如降级处理中，你返回了降级数据，然后需要 return nil)。）

## Go1.13 error

函数在调用栈中添加信息向上传递错误，例如对错误发生时发生的情况的简要描述。

```go
if err != nil {
    return fmt.Errorf("decompress %v:%v", name, err)
}
```

使用创建新错误 fmt.Errorf 丢弃原始错误中除文本外的所有内容。正如我们在上面的QueryError 中看到的那样，我们有时可能需要定义一个包含底层错误的新错误类型，并将其保存以供代码检查。这里是 QueryError：

```go
type QueryError struct {
    Query string
    Err   error
}
```

程序可以查看 QueryError \p值以根据底层错误做出决策。

```go
if e, ok := err.(*Queryerror); ok && e.Err == ErrPermission {
    //query failed because of a permission problem
}
```

go1.13为 errors 和 fmt 标准库包引入了新特性，以简化处理包含其他错误的错误。其中最重要的是: 包含另一个错误的 error 可以实现返回底层错误的 Unwrap 方法。如果 e1.Unwrap() 返回 e2，那么我们说 e1 包装 e2，您可以展开 e1 以获得 e2。

按照此约定，我们可以为上面的 QueryError 类型指定一个 Unwrap 方法，该方法返回其包含的错误:

```go
func (e *Queryerror) Unwrap() error { return e.Err }
```

go1.13 errors 包包含两个用于检查错误的新函数：Is 和 As。

```go
// Similar to:
// if err = Errnotfound {...}
if errors.Is(err, Errnotfound) {
    // something wasnt found
}

// Similar to
// if e, ok := err.(*Queryerror); ok {...}
var e *Queryerror
// Note: *Queryerror is the type of the error
if errorsAs(err, &e) {
    // err is a *Queryerror, and e is set to the errors value
}
```

### Wrapping errors with %w

如前所述，使用 `fmt.Errorf` 向错误添加附加信息。

```go
if err != nil {
        return fmt.Errorf("decompress %v:%v", name, err)
}
```

在 Go 1.13中 `fmt.Error`f 支持新的 `%w` 谓词。

```go
if err != nil {
        return fmt.Errorf("decompress %v:%w", name, err)
}
```

用 `%w` 包装错误可用于 `errors.Is` 以及 `errors.As`

```go
err := fmt.Errorf("access denied: % W", Errpermission)
if errors.Is(err, Errpermission) {
    // ...
}
```

## Go2介绍

https://go.googlesource.com/proposal/+/master/design/29934-error-values.md

## 参考文章

- https://u.geekbang.org/subject/go
- https://lailin.xyz/post/go-training-03.html
