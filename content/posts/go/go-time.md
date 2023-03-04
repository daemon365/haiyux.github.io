---
title: "Go time包"
date: 2020-02-20T11:26:32+08:00
draft: false
toc: true
categories: [go]
tags: [golang]
authors:
    - haiyux
featuredImagePreview: /img/go.webp
---


## 时间类型

time.Time类型表示时间。

```go
func demo() {
	now := time.Now() //获取当前时间
	fmt.Printf("Now:%v\n", now)  // Now:2020-08-19 21:53:31.1633023 +0800 CST m=+0.003989401
	year := now.Year()     //年
	month := now.Month()   //月
	day := now.Day()       //日
	hour := now.Hour()     //小时
	minute := now.Minute() //分钟
	second := now.Second() //秒
	fmt.Printf("%d-%02d-%02d %02d:%02d:%02d\n", year, month, day, hour, minute, second) // 2020-08-19 21:53:31
}
```

## 时间戳

```go
func stamp() {
	now := time.Now()            //获取当前时间
	timestamp1 := now.Unix()     //时间戳
	timestamp2 := now.UnixNano() //纳秒时间戳
    fmt.Printf("秒时间戳:%v\n", timestamp1) // 秒时间戳:1597845356
	fmt.Printf("纳秒时间戳:%v\n", timestamp2) // 纳秒时间戳:1597845356562315400
}
```

使用time.Unix()函数可以将时间戳转为时间格式。

```go
func demo2(timestamp int64) {
	timeObj := time.Unix(1462032000, 0) //将时间戳转为时间格式
    fmt.Println(timeObj) // 2016-05-01 00:00:00 +0800 CST
}
```

## 时间格式化

时间类型有一个自带的方法Format进行格式化，需要注意的是Go语言中格式化时间模板不是常见的Y-m-d H:M:S而是使用Go的诞生时间2006年1月2号15点04分

```go
func demo4() {
	now := time.Now()
	fmt.Println(now.Format("2006-01-02 15:04:05.000 Mon Jan")) // 2020-08-19 22:02:46.296 Wed Aug
	fmt.Println(now.Format("2006-01-02 03:04:05.000 PM Mon Jan")) // 2020-08-19 10:02:46.296 PM Wed Aug
	fmt.Println(now.Format("2006*01*02")) // 2020*08*19
}
```

**解析字符串格式的时间**

```go
// 加载时区
loc, err := time.LoadLocation("Asia/Shanghai")
if err != nil {
    fmt.Println(err)
    return
}
// 解析字符串时间
timeObj, err := time.ParseInLocation("2006/01/02 15:04:05", "2016/04/30 22:00:00", loc)
if err != nil {
    fmt.Println(err)
    return
}
fmt.Println(timeObj) // 2016-04-30 22:00:00 +0800 CST
fmt.Println(timeObj.Unix()) // 1462024800
```

## 时间操作

*   func (t Time) Add(d Duration) Time加时间
*   func (t Time) Sub(u Time) Duration减时间
*   func (t Time) Before(u Time) bool在u之前
*   func (t Time) After(u Time) bool在u之后

```go
package main
import (
	"fmt"
	"time"
)
func formatDemo() {
	now := time.Now()
	fmt.Println(now.Format("2006-01-02 15:04:05.000 Mon Jan"))    // 2020-08-19 22:02:46.296 Wed Aug
	fmt.Println(now.Format("2006-01-02 03:04:05.000 PM Mon Jan")) // 2020-08-19 10:02:46.296 PM Wed Aug
	fmt.Println(now.Format("2006*01*02"))                         // 2020*08*19
}
func main() {
	// 加载时区
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		fmt.Println(err)
		return
	}
	// 解析字符串时间
	timeObj, err := time.ParseInLocation("2006/01/02 15:04:05", "2016/04/30 22:00:00", loc)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(timeObj) // 2016-04-30 22:00:00 +0800 CST

	now := time.Now()
	a := now.Add(time.Hour) 
	fmt.Println(a)   // 2020-08-19 23:15:30.0153059 +0800 CST m=+3600.002023801
	s := now.Sub(timeObj)
	fmt.Println(s) // 37728h15m30.0153059s
	fmt.Println(now.Before(timeObj)) // false
	fmt.Println(now.After(timeObj)) // true
}
```

## 定时器

使用time.Tick(时间间隔)来设置定时器，定时器的本质上是一个channel

```go
func tickDemo() {
	ticker := time.Tick(time.Second) //定义一个1秒间隔的定时器
	for i := range ticker {
		fmt.Println(i) //每秒都会打印时间
	}
}
```