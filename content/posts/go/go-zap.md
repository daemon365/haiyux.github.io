---
title: "Go zap高性能日志"
date: 2021-01-12T11:36:55+08:00
draft: false
toc: true
categories: [go]
tags: [golang]
authors:
    - haiyux
---


## 摘要

日志在整个工程实践中的重要性不言而喻，在选择日志组件的时候也有多方面的考量。详细、正确和及时的反馈是必不可少的，但是整个性能表现是否也是必要考虑的点呢？在长期的实践中发现有的日志组件对于计算资源的消耗十分巨大，这将导致整个服务成本的居高不下。此文从设计原理深度分析了 zap 的设计与实现上的权衡，也希望整个的选择、考量的过程能给其他的技术团队在开发高性能的 Go 组件时带来一定的借鉴意义。

## 前言

日志作为整个代码行为的记录，是程序执行逻辑和异常最直接的反馈。对于整个系统来说，日志是至关重要的组成部分。通过分析日志我们不仅可以发现系统的问题，同时日志中也蕴含了大量有价值可以被挖掘的信息，因此合理地记录日志是十分必要的。

我们的业务通常会记录大量的 Debug 日志，但在实际测试过程中，发现我们使用的日志库 seelog 性能存在严重的瓶颈，在我们的对比结果中发现：zap 表现非常突出，单线程 Qps 也是 logrus、seelog 的数倍。

在分析源码后 zap 设计与实现上的考量让我感到受益颇多，在这里我们主要分享一下以下几个方面：

1.  zap 为何有这么高的性能
2.  对于我们自己的开发有什么值得借鉴的地方
3.  如何正确的使用 Go 开发高性能的组件

## 为什么选择使用ZAP

*   它同时提供了结构化日志记录和printf风格的日志记录
*   它非常的快

根据Uber-go Zap的文档，它的性能比类似的结构化日志包更好——也比标准库更快。 以下是Zap发布的基准测试信息

记录一条消息和10个字段:

|     Package     |    Time     | Time % to zap | Objects Allocated |
| :-------------: | :---------: | :-----------: | :---------------: |
|      ⚡️ zap      |  862 ns/op  |      +0%      |    5 allocs/op    |
| ⚡️ zap (sugared) | 1250 ns/op  |     +45%      |   11 allocs/op    |
|     zerolog     | 4021 ns/op  |     +366%     |   76 allocs/op    |
|     go-kit      | 4542 ns/op  |     +427%     |   105 allocs/op   |
|    apex/log     | 26785 ns/op |    +3007%     |   115 allocs/op   |
|     logrus      | 29501 ns/op |    +3322%     |   125 allocs/op   |
|      log15      | 29906 ns/op |    +3369%     |   122 allocs/op   |

记录一个静态字符串，没有任何上下文或printf风格的模板：

|     Package      |    Time    | Time % to zap | Objects Allocated |
| :--------------: | :--------: | :-----------: | :---------------: |
|      ⚡️ zap       | 118 ns/op  |      +0%      |    0 allocs/op    |
| ⚡️ zap (sugared)  | 191 ns/op  |     +62%      |    2 allocs/op    |
|     zerolog      |  93 ns/op  |     -21%      |    0 allocs/op    |
|      go-kit      | 280 ns/op  |     +137%     |   11 allocs/op    |
| standard library | 499 ns/op  |     +323%     |    2 allocs/op    |
|     apex/log     | 1990 ns/op |    +1586%     |   10 allocs/op    |
|      logrus      | 3129 ns/op |    +2552%     |   24 allocs/op    |
|      log15       | 3887 ns/op |    +3194%     |   23 allocs/op    |

## 安装

```bash
go get -u go.uber.org/zap
```

## 示例

### 简单示例

#### 格式化输出

```go
package main
import (
    "go.uber.org/zap"
    "time"
)
func main() {
    // zap.NewDevelopment 格式化输出
    logger, _ := zap.ewDevelopment()
    defer logger.Sync()
    logger.Info("无法获取网址",
        zap.String("url", "http://www.baidu.com"),
        zap.Int("attempt", 3),
        zap.Duration("backoff", time.Second),
    )
}
```

格式化输出打印结果：

```go
2019-01-02T15:01:13.923+0800    INFO    spikeProxy/main.go:17   failed to fetch URL {"url": "http://www.baidu.com", "attempt": 3, "backoff": "1s"}
```

#### json 序列化输出

```go
package main
import (
    "go.uber.org/zap"
    "time"
)
func main() {
   // zap.NewProduction json序列化输出
    logger, _ := zap.NewProduction()
    defer logger.Sync()
    logger.Info("无法获取网址",
        zap.String("url", "http://www.baidu.com"),
        zap.Int("attempt", 3),
        zap.Duration("backoff", time.Second),
    )
}
```

json序列化输出打印结果：

```go
{"level":"info","ts":1546413239.1466308,"caller":"spikeProxy/main.go:16","msg":"无法获取网址","url":"http://www.baidu.com","attempt":3,"backoff":1}
```

### 自定义示例

选择一个日志库除了高性能是考量的一个标准，高扩展也非常重要，例如：json key 自定义、时间格式化、日志级别等。

```go
package main
import (
    "go.uber.org/zap"
    "go.uber.org/zap/zapcore"
    "fmt"
    "time"
)
func main() {
    encoderConfig := zapcore.EncoderConfig{
        TimeKey:        "time",
        LevelKey:       "level",
        NameKey:        "logger",
        CallerKey:      "caller",
        MessageKey:     "msg",
        StacktraceKey:  "stacktrace",
        LineEnding:     zapcore.DefaultLineEnding,
        EncodeLevel:    zapcore.LowercaseLevelEncoder,  // 小写编码器
        EncodeTime:     zapcore.ISO8601TimeEncoder,     // ISO8601 UTC 时间格式
        EncodeDuration: zapcore.SecondsDurationEncoder,
        EncodeCaller:   zapcore.FullCallerEncoder,      // 全路径编码器
    }
    // 设置日志级别
    atom := zap.NewAtomicLevelAt(zap.DebugLevel)
    config := zap.Config{
        Level:            atom,                                                // 日志级别
        Development:      true,                                                // 开发模式，堆栈跟踪
        Encoding:         "json",                                              // 输出格式 console 或 json
        EncoderConfig:    encoderConfig,                                       // 编码器配置
        InitialFields:    map[string]interface{}{"serviceName": "spikeProxy"}, // 初始化字段，如：添加一个服务器名称
        OutputPaths:      []string{"stdout", "./logs/spikeProxy.log"},         // 输出到指定文件 stdout（标准输出，正常颜色） stderr（错误输出，红色）
        ErrorOutputPaths: []string{"stderr"},
    }
    // 构建日志
    logger, err := config.Build()
    if err != nil {
        panic(fmt.Sprintf("log 初始化失败: %v", err))
    }
    logger.Info("log 初始化成功")
    logger.Info("无法获取网址",
        zap.String("url", "http://www.baidu.com"),
        zap.Int("attempt", 3),
        zap.Duration("backoff", time.Second),
    )
}
```

打印结果：

```go
{"level":"info","time":"2019-01-02T15:38:33.778+0800","caller":"/Users/lcl/go/src/spikeProxy/main.go:54","msg":"log 初始化成功","serviceName":"spikeProxy"}
{"level":"info","time":"2019-01-02T15:38:33.778+0800","caller":"/Users/lcl/go/src/spikeProxy/main.go:56","msg":"无法获取网址","serviceName":"spikeProxy","url":"http://www.baidu.com","attempt":3,"backoff":1}
```

## 写入归档文件示例

## 安装 lumberjack

```go
go get gopkg.in/natefinch/lumberjack.v2
```

## lumberjack介绍

Lumberjack是一个Go包，用于将日志写入滚动文件。
zap 不支持文件归档，如果要支持文件按大小或者时间归档，需要使用lumberjack，lumberjack也是[zap官方推荐](https://github.com/uber-go/zap/blob/master/FAQ.md)的。

## 示例

```go
package main
import (
    "go.uber.org/zap"
    "go.uber.org/zap/zapcore"
    "time"
    "gopkg.in/natefinch/lumberjack.v2"
    "os"
)
func main() {
    hook := lumberjack.Logger{
        Filename:   "./logs/spikeProxy1.log", // 日志文件路径
        MaxSize:    128,                      // 每个日志文件保存的最大尺寸 单位：M
        MaxBackups: 30,                       // 日志文件最多保存多少个备份
        MaxAge:     7,                        // 文件最多保存多少天
        Compress:   true,                     // 是否压缩
    }
    encoderConfig := zapcore.EncoderConfig{
        TimeKey:        "time",
        LevelKey:       "level",
        NameKey:        "logger",
        CallerKey:      "linenum",
        MessageKey:     "msg",
        StacktraceKey:  "stacktrace",
        LineEnding:     zapcore.DefaultLineEnding,
        EncodeLevel:    zapcore.LowercaseLevelEncoder,  // 小写编码器
        EncodeTime:     zapcore.ISO8601TimeEncoder,     // ISO8601 UTC 时间格式
        EncodeDuration: zapcore.SecondsDurationEncoder, //
        EncodeCaller:   zapcore.FullCallerEncoder,      // 全路径编码器
        EncodeName:     zapcore.FullNameEncoder,
    }
    // 设置日志级别
    atomicLevel := zap.NewAtomicLevel()
    atomicLevel.SetLevel(zap.InfoLevel)
    core := zapcore.NewCore(
        zapcore.NewJSONEncoder(encoderConfig),                                           // 编码器配置
        zapcore.NewMultiWriteSyncer(zapcore.AddSync(os.Stdout), zapcore.AddSync(&hook)), // 打印到控制台和文件
        atomicLevel,                                                                     // 日志级别
    )
    // 开启开发模式，堆栈跟踪
    caller := zap.AddCaller()
    // 开启文件及行号
    development := zap.Development()
    // 设置初始化字段
    filed := zap.Fields(zap.String("serviceName", "serviceName"))
    // 构造日志
    logger := zap.New(core, caller, development, filed)
    logger.Info("log 初始化成功")
    logger.Info("无法获取网址",
        zap.String("url", "http://www.baidu.com"),
        zap.Int("attempt", 3),
        zap.Duration("backoff", time.Second))
}
```

控制台打印结果：

```go
{"level":"info","time":"2019-01-02T16:14:43.608+0800","linenum":"/Users/lcl/go/src/spikeProxy/main.go:56","msg":"log 初始化成功","serviceName":"serviceName"}
{"level":"info","time":"2019-01-02T16:14:43.608+0800","linenum":"/Users/lcl/go/src/spikeProxy/main.go:57","msg":"无法获取网址","serviceName":"serviceName","url":"http://www.baidu.com","attempt":3,"backoff":1}
```

文件打印结果：

```go
{"level":"info","time":"2019-01-02T16:14:43.608+0800","linenum":"/Users/lcl/go/src/spikeProxy/main.go:56","msg":"log 初始化成功","serviceName":"serviceName"}
{"level":"info","time":"2019-01-02T16:14:43.608+0800","linenum":"/Users/lcl/go/src/spikeProxy/main.go:57","msg":"无法获取网址","serviceName":"serviceName","url":"http://www.baidu.com","attempt":3,"backoff":1}
```

## gin框架使用zap+lumberjack

### 初始化zap,lumberjack

```go
// viperconfig
type Log struct {
	FileName   string `yaml:"filename"`
	MaxSize    int    `yaml:"maxsize"`
	MaxBackups int    `yaml:"maxbackups"`
	MaxAges    int    `yaml:"maxages"`
	Compress   bool   `yaml:"compress"`
	Level      string `yaml:"-"`
}
```
```go
// init
var ZapLog *zap.Logger
// InitLogger 初始化Logger
func InitLogger(cfg *viperConfig.Log) (err error) {
	writeSyncer := getLogWriter(cfg.FileName, cfg.MaxSize, cfg.MaxBackups, cfg.MaxAges)
	encoder := getEncoder()
	var l = new(zapcore.Level)
	err = l.UnmarshalText([]byte(cfg.Level))
	if err != nil {
		return
	}
	core := zapcore.NewCore(encoder, writeSyncer, l)
	ZapLog = zap.New(core, zap.AddCaller())
	zap.ReplaceGlobals(ZapLog) // 替换zap包中全局的logger实例，后续在其他包中只需使用zap.L()调用即可
	return
}
func getEncoder() zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.TimeKey = "time"
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	encoderConfig.EncodeDuration = zapcore.SecondsDurationEncoder
	encoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
	return zapcore.NewJSONEncoder(encoderConfig)
}
func getLogWriter(filename string, maxSize, maxBackup, maxAge int) zapcore.WriteSyncer {
	lumberJackLogger := &lumberjack.Logger{
		Filename:   filename,
		MaxSize:    maxSize,
		MaxBackups: maxBackup,
		MaxAge:     maxAge,
	}
	return zapcore.AddSync(lumberJackLogger)
}
```

### gin日志中间件

模仿Logger()和Recovery()的实现，使用我们的日志库来接收gin框架默认输出的日志。

```go
// GinLogger 接收gin框架默认的日志
func GinLogger(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery
		c.Next()
		cost := time.S***art)
		logger.Info(path,
			zap.Int("status", c.Writer.Status()),
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.String("query", query),
			zap.String("ip", c.ClientIP()),
			zap.String("user-agent", c.Request.UserAgent()),
			zap.String("errors", c.Errors.ByType(gin.ErrorTypePrivate).String()),
			zap.Duration("cost", cost),
		)
	}
}
// GinRecovery recover掉项目可能出现的panic
func GinRecovery(logger *zap.Logger, stack bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// Check for a broken connection, as it is not really a
				// condition that warrants a panic stack trace.
				var brokenPipe bool
				if ne, ok := err.(*net.OpError); ok {
					if se, ok := ne.Err.(*os.SyscallError); ok {
						if strings.Contains(strings.ToLower(se.Error()), "broken pipe") || strings.Contains(strings.ToLower(se.Error()), "connection reset by peer") {
							brokenPipe = true
						}
					}
				}
				httpRequest, _ := httputil.DumpRequest(c.Request, false)
				if brokenPipe {
					logger.Error(c.Request.URL.Path,
						zap.Any("error", err),
						zap.String("request", string(httpRequest)),
					)
					// If the connection is dead, we can't write a status to it.
					c.Error(err.(error)) // nolint: errcheck
					c.Abort()
					return
				}
				if stack {
					logger.Error("[Recovery from panic]",
						zap.Any("error", err),
						zap.String("request", string(httpRequest)),
						zap.String("stack", string(debug.Stack())),
					)
				} else {
					logger.Error("[Recovery from panic]",
						zap.Any("error", err),
						zap.String("request", string(httpRequest)),
					)
				}
				c.AbortWithStatus(http.StatusInternalServerError)
			}
		}()
		c.Next()
	}
}
```

使用

```go
// 全局中间件
func InitMiddleWares(eng *gin.Engine) {
	eng.Use(GinLogger(log.ZapLog), GinRecovery(log.ZapLog, true))
}
```

参考文章:

*   [https://mp.weixin.qq.com/s/i0bMh_gLLrdnhAEWlF-xDw](https://mp.weixin.qq.com/s/i0bMh_gLLrdnhAEWlF-xDw)
*   [https://studygolang.com/articles/17394](https://studygolang.com/articles/17394) 
