---
title: "Kratos日志库的使用姿势"
date: 2021-08-19T18:11:50+08:00
draft: false
toc: true
categories: [microservice,go]
authors:
    - haiyux
---

## 什么是日志

> 所谓日志（Log）是指系统所指定对象的某些操作和其操作结果按时间有序的集合。log文件就是日志文件，log文件记录了系统和系统的用户之间交互的信息，是自动捕获人与系统终端之间交互的类型、内容或时间的数据收集方法。

日志是用来记录，用户操作，系统状态，错误信息等等内容的文件，是一个软件系统的重要组成部分。一个良好的日志规范，对于系统运行状态的分析，以及线上问题的解决具有重大的意义。

### 日志规范

在开发软件打印日志时，需要注意一些问题，举例可能不全，可以自行百度相关文章或查看文章底部文献：

- 重要功能日志尽可能的完善。
- 不要随意打印无用的日志，过多无用的日志会增加分析日志的难度。
- 日志要区分等级 如 debug，warn，info，error 等。
- 捕获到未处理错误时最好打印错误堆栈信息

### Go 语言常用的日志库

Go 语言标准库中就为我们提供了一个日志库 **log**，除了这个以外还有很多日志库，如 **logrus**，**glog**，**logx**，**Uber** 的 **zap** 等等，例如 **zap** 就有很多的优点：

- 高性能
- 配置项丰富
- 多种日志级别
- 支持Hook
- 丰富的工具包
- 提供了sugar log
- 多种日志打印格式
- ...
  
  ##### 简单使用

```golang
package main

import (
    "errors"
    "go.uber.org/zap"
)

var logger *zap.Logger

func init() {
    logger, _ = zap.NewProduction()
}
func main() {
    logger.Error(
        "My name is baobao",
        zap.String("from", "Hulun Buir"),
        zap.Error(errors.New("no good")))

    logger.Info("Worked in the Ministry of national development of China!",
        zap.String("key", "eat🍚"),
        zap.String("key", "sleep😴"))
    defer logger.Sync()
}
```

## Kratos 日志库原理解析

> 在私下与 **Tony老师** 沟通时关于日志库的实现理念时，**Tony老师** 说：由于目前日志库非常多并且好用，在 **Kratos** 的日志中，主要考虑以下几个问题：
> 
> 1. 统一日志接口设计
> 2. 组织结构化日志
> 3. 并且需要有友好的日志级别使用
> 4. 支持多输出源对接需求，如log-agent 或者 3rd 日志库

**kratos** 的日志库，不强制具体实现方式，只提供适配器，用户可以自行实现日志功能，只需要实现**kratos/log** 的 **Logger interface** 即可接入自己喜欢的日志系统。

**kratos** 的日志库，在设计阶段，参考了很多优秀的开源项目和大厂的日志系统实现，经历了多次改动后才呈现给大家。

### log库的组成

**kratos** 的 **log** 库主要由以下几个文件组成

- **level.go** 定义日志级别
- **log.go** 日志核心
- **helper.go** **log**的**helper**
- **value.go** 实现动态值
  
  ### 源码分析
  
  **kratos** 的 **log** 库中, 核心部分就是 **log.go** 代码非常简洁，符合 **kratos** 的设计理念。 **log.go** 中声明了 **Logger interface**，用户只需要实现接口，即可引入自己的日志实现，主要代码如下：

#### **log.go**

```golang
package log

import (
    "context"
    "log"
)

var (
    // DefaultLogger is default logger.
    DefaultLogger Logger = NewStdLogger(log.Writer())
)

// Logger 接口, 后面实现自定义日志库的时候，就是要实现这个接口。
type Logger interface {
    Log(level Level, keyvals ...interface{}) error
}

type logger struct {
    logs      []Logger // logger 数组
    prefix    []interface{} // 一些默认打印的值,例如通过 With 绑定的 Valuer
    hasValuer bool // 是否包含 Valuer 
    ctx       context.Context // 上下文
}

func (c *logger) Log(level Level, keyvals ...interface{}) error {
    kvs := make([]interface{}, 0, len(c.prefix)+len(keyvals))
    kvs = append(kvs, c.prefix...)
        // 判断是否存在 valuer
    if c.hasValuer {
                // 绑定 valuer
        bindValues(c.ctx, kvs)
    }
    kvs = append(kvs, keyvals...)
        // 遍历 logs，调用所有的 logger 进行日志打印。
    for _, l := range c.logs {
        if err := l.Log(level, kvs...); err != nil {
            return err
        }
    }
    return nil
}

// With with logger fields.
func With(l Logger, kv ...interface{}) Logger {
    // 判断是否能 把传入的 logger 断言成 *logger
    if c, ok := l.(*logger); ok {
        // 预分配内存,make了一个空间长度为 c.prefix + keyvals长度的 interface数组
        kvs := make([]interface{}, 0, len(c.prefix)+len(kv))
        // 处理打印的内容
        kvs = append(kvs, kv...)
        kvs = append(kvs, c.prefix...)
        // containsValuer()用来判断 kvs 里面是否存在 valuer
        return &logger{
            logs:      c.logs,
            prefix:    kvs,
            hasValuer: containsValuer(kvs),
            ctx:       c.ctx,
        }
    }
    return &logger{logs: []Logger{l}, prefix: kv, hasValuer: containsValuer(kv)}
}

// WithContext 绑定 ctx,注意 ctx 必须非空
func WithContext(ctx context.Context, l Logger) Logger {
    if c, ok := l.(*logger); ok {
        return &logger{
            logs:      c.logs,
            prefix:    c.prefix,
            hasValuer: c.hasValuer,
            ctx:       ctx,
        }
    }
    return &logger{logs: []Logger{l}, ctx: ctx}
}

// MultiLogger 包装多个logger，简单说就是同时使用多个logger打印
func MultiLogger(logs ...Logger) Logger {
    return &logger{logs: logs}
}
```

#### value.go

```golang
// 返回 valuer 函数.
func Value(ctx context.Context, v interface{}) interface{} {
    if v, ok := v.(Valuer); ok {
        return v(ctx)
    }
    return v
}

// ...省略一些内置的 valuer 实现

// 绑定 valuer
func bindValues(ctx context.Context, keyvals []interface{}) {
    for i := 1; i < len(keyvals); i += 2 {
        if v, ok := keyvals[i].(Valuer); ok {
            keyvals[i] = v(ctx)
        }
    }
}

// 是否包含 valuer
func containsValuer(keyvals []interface{}) bool {
    for i := 1; i < len(keyvals); i += 2 {
        if _, ok := keyvals[i].(Valuer); ok {
            return true
        }
    }
    return false
}
```

#### helper.go

```golang
package log

import (
    "context"
    "fmt"
)

// Helper is a logger helper.
type Helper struct {
    logger Logger
}

// 创建一个 logger helper 实例
func NewHelper(logger Logger) *Helper {
    return &Helper{
        logger: logger,
    }
}

// 通过 WithContext() 返回包含 ctx 的一个日志的帮助类，包含一些定义好的按级别打印日志的方法
func (h *Helper) WithContext(ctx context.Context) *Helper {
    return &Helper{
        logger: WithContext(ctx, h.logger),
    }
}

func (h *Helper) Log(level Level, keyvals ...interface{}) {
    h.logger.Log(level, keyvals...)
}

func (h *Helper) Debug(a ...interface{}) {
    h.logger.Log(LevelDebug, "msg", fmt.Sprint(a...))
}

func (h *Helper) Debugf(format string, a ...interface{}) {
    h.logger.Log(LevelDebug, "msg", fmt.Sprintf(format, a...))
}

// ...省略一些重复的方法
```

#### 通过单元测试了解调用逻辑

```golang
func TestInfo(t *testing.T) {
    logger := DefaultLogger
    logger = With(logger, "ts", DefaultTimestamp, "caller", DefaultCaller)
    logger.Log(LevelInfo, "key1", "value1")
}
```

1. 单测中首先声明了一个 **logger** ，用的默认的 **DefaultLogger**
2. 调用 **log.go** 中的 **With()** 函数， 传入了 **logger** ,和两个动态值， **DefaultTimestamp** 和 **DefaultCaller**。
3. With方法被调用，判断是否能将参数 **l** 类型转换成 **\*logger**
4. 如果可以转换，将传入的KV，赋值给 **logger.prefix** 上，然后调用 **value.go** 中的 **containsValuer()** 判断传入的KV中是否存在 Valuer类型的值，将结果赋值给 **context.hasValuer**，最后返回 **Logger** 对象
5. 否则则直接返回一个 **&logger{logs: []Logger{l}, prefix: kv, hasValuer: containsValuer(kv)}**
6. 然后打印日志时，**logger struct** 的 **Log** 方法被调用
7. **Log()** 方法首先预分配了 **keyvals** 的空间，然后判断 **hasValuer**，如果为 **true**，则调用 **valuer.go** 中的 **bindValuer()** 并传入了 **ctx** 然后获取 **valuer** 的值`if v, ok := v.(Valuer); ok {
   
        return v()
   
    }`

8.最后遍历 **logger.logs** 打印日志

## 使用方法

### 使用 Logger 打印日志

```go
logger := log.DefaultLogger
logger.Log(LevelInfo, "key1", "value1")
```

### 使用 Helper 打印日志

```go
log := log.NewHelper(DefaultLogger)
log.Debug("test debug")
log.Info("test info")
log.Warn("test warn")
log.Error("test error")
```

### 使用 valuer

```go
logger := DefaultLogger
logger = With(logger, "ts", DefaultTimestamp, "caller", DefaultCaller)
logger.Log(LevelInfo, "msg", "helloworld")
```

### 同时打印多个 logger

```go
out := log.NewStdLogger(os.Stdout)
err := log.NewStdLogger(os.Stderr)
l := log.With(MultiLogger(out, err))
l.Log(LevelInfo, "msg", "test")
```

### 使用 context

```go
logger := log.With(NewStdLogger(os.Stdout),
    "trace", Trace(),
)
log := log.NewHelper(logger)
ctx := context.WithValue(context.Background(), "trace_id", "2233")
log.WithContext(ctx).Info("got trace!")
```

### 使用 filter 过滤日志

如果需要过滤日志中某些不应该被打印明文的字段如 password 等，可以通过 log.NewFilter() 来实现过滤功能。

#### 通过 level 过滤日志

```go
l := log.NewHelper(log.NewFilter(log.DefaultLogger, log.FilterLevel(log.LevelWarn)))
l.Log(LevelDebug, "msg1", "te1st debug")
l.Debug("test debug")
l.Debugf("test %s", "debug")
l.Debugw("log", "test debug")
l.Warn("warn log")
```

#### 通过 key 过滤日志

```go
l := log.NewHelper(log.NewFilter(log.DefaultLogger, log.FilterKey("password")))
l.Debugw("password", "123456")
```

##### 通过 value 过滤日志

```go
l := log.NewHelper(log.NewFilter(log.DefaultLogger, log.FilterValue("kratos")))
l.Debugw("name", "kratos")
```

#### 通过 hook func 过滤日志

```go
l := log.NewHelper(log.NewFilter(log.DefaultLogger, log.FilterFunc(testFilterFunc)))
l.Debug("debug level")
l.Infow("password", "123456")
func testFilterFunc(level Level, keyvals ...interface{}) bool {
    if level == LevelWarn {
        return true
    }
    for i := 0; i < len(keyvals); i++ {
        if keyvals[i] == "password" {
            keyvals[i+1] = "***"
        }
    }
    return false
}
```

## 用 Zap 实现 kratos 的日志接口

实现的代码十分简单，仅有不到100 行代码，仅供大家参考。

### 实现

```golang
// kratos/examples/log/zap.go
package logger

import (
    "fmt"
        "os"

    "github.com/go-kratos/kratos/v2/log"
    "go.uber.org/zap"
    "go.uber.org/zap/zapcore"
    "gopkg.in/natefinch/lumberjack.v2"
)

var _ log.Logger = (*ZapLogger)(nil)

// Zap 结构体
type ZapLogger struct {
    log  *zap.Logger
    Sync func() error
}

// 创建一个 ZapLogger 实例
func NewZapLogger(encoder zapcore.EncoderConfig, level zap.AtomicLevel, opts ...zap.Option) *ZapLogger {
    writeSyncer := getLogWriter()
    // 设置 zapcore
    core := zapcore.NewCore(
        zapcore.NewConsoleEncoder(encoder),
        zapcore.NewMultiWriteSyncer(
            zapcore.AddSync(os.Stdout),
        ), level)
    //  new 一个 *zap.Logger
    zapLogger := zap.New(core, opts...)
    return &ZapLogger{log: zapLogger, Sync: zapLogger.Sync}
}

// Log 方法实现了 kratos/log/log.go 中的 Logger interface
func (l *ZapLogger) Log(level log.Level, keyvals ...interface{}) error {
    if len(keyvals) == 0 || len(keyvals)%2 != 0{
            l.log.Warn(fmt.Sprint("Keyvalues must appear in pairs: ", keyvals))
        return nil
    }
    // 按照 KV 传入的时候,使用的 zap.Field
    var data []zap.Field
    for i := 0; i < len(keyvals); i += 2 {
        data = append(data, zap.Any(fmt.Sprint(keyvals[i]), fmt.Sprint(keyvals[i+1])))
    }
    switch level {
    case log.LevelDebug:
        l.log.Debug("", data...)
    case log.LevelInfo:
        l.log.Info("", data...)
    case log.LevelWarn:
        l.log.Warn("", data...)
    case log.LevelError:
        l.log.Error("", data...)
    }
    return nil
}

// 日志自动切割，采用 lumberjack 实现的
func getLogWriter() zapcore.WriteSyncer {
    lumberJackLogger := &lumberjack.Logger{
        Filename:   "./test.log",
        MaxSize:    10,
        MaxBackups: 5,
        MaxAge:     30,
        Compress:   false,
    }
    return zapcore.AddSync(lumberJackLogger)
}
```

### 使用方法

```golang
// kratos/examples/log/zap_test.go
package logger

import (
    "testing"

    "github.com/go-kratos/kratos/v2/log"
    "go.uber.org/zap"
    "go.uber.org/zap/zapcore"
)

func TestZapLogger(t *testing.T) {
    encoder := zapcore.EncoderConfig{
        TimeKey:        "t",
        LevelKey:       "level",
        NameKey:        "logger",
        CallerKey:      "caller",
        MessageKey:     "msg",
        StacktraceKey:  "stack",
        EncodeTime:     zapcore.ISO8601TimeEncoder,
        LineEnding:     zapcore.DefaultLineEnding,
        EncodeLevel:    zapcore.LowercaseLevelEncoder,
        EncodeDuration: zapcore.SecondsDurationEncoder,
        EncodeCaller:   zapcore.FullCallerEncoder,
    }
    logger := NewZapLogger(
        encoder,
        zap.NewAtomicLevelAt(zapcore.DebugLevel),
        zap.AddStacktrace(
            zap.NewAtomicLevelAt(zapcore.ErrorLevel)),
        zap.AddCallerSkip(2),
        zap.Development(),
    )
    zlog := log.NewHelper(logger)
    zlog.Infow("name","go 语言进阶")
    defer logger.Sync()
}
```

## 参考文献

- 关于 log 库的讨论 [issue](https://github.com/go-kratos/kratos/issues/882)
- Uber 的日志库 Zap [uber/zap](https://github.com/uber-go/zap)
- 日志割接库 [lumberjack](https://github.com/natefinch/lumberjack)
- 基于 zap 的日志demo [log example ](https://github.com/go-kratos/kratos/tree/main/examples/log)

---

![](/images/2344773-20210902225224456-315933124.png)

![](/images/2344773-20210902225203602-1750987546.gif)
