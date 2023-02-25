---
title: "结构型模式"
date: 2022-04-27T15:04:58+08:00
draft: false
toc: true
categories: 
- "design mode"
tags: 
- 设计模式
authors:
- haiyux
---


## 适配器模式

适配器模式用于转换一种接口适配另一种接口。比如，现在有个借口是对`json`字符串进行分析等，现在有一些`yaml`文件也要分析，这时候我我们就应该给`yaml`字符串就个适配器，转换成`json`字符串，然后就行分析。

### 代码实现

```go
package main

import (
	"fmt"

	"github.com/ghodss/yaml"
)

type Analysis interface {
	Analyze(string) error
}

type JsonAnalysis struct{}

func (*JsonAnalysis) Analyze(jsonStr string) error {
	// 函数逻辑
	fmt.Println(jsonStr)
	return nil
}

type yamlAnalysis struct {
	ja *JsonAnalysis
}

func (y *yamlAnalysis) Analyze(yamlStr string) error {
	bs, err := yaml.YAMLToJSON([]byte(yamlStr))
	if err != nil {
		return err
	}
	return y.ja.Analyze(string(bs))
}

func main() {
	ja := &JsonAnalysis{}
	err := ja.Analyze("{\"name\":\"zhy\",\"age\":18}")
	if err != nil {
		fmt.Println(err)
	}
	ya := &yamlAnalysis{ja: ja}
	err = ya.Analyze("name: you\nage: 88")
	if err != nil {
		fmt.Println(err)
	}
}

/*
{"name":"zhy","age":18}
{"age":88,"name":"you"}
*/
```

## 桥接模式

桥接模式分离抽象部分和实现部分。使得两部分独立扩展。

桥接模式类似于策略模式，区别在于策略模式封装一系列算法使得算法可以互相替换。

策略模式使抽象部分和实现部分分离，可以独立变化。

比如要发消息，可以发很多种方式，微信、qq、email、短信等等，也可以发很多类型，日常、紧急等的。这时我们可以把发送的的方法做抽象，把类型做实现。

### 代码实现

```go
package main

import "fmt"

type Message interface {
	SendMessage(s string) error
}

type MessageMethod interface {
	Send(string) error
}

type qq struct{}

func (*qq) Send(s string) error {
	fmt.Println("send qq:", s)
	return nil
}

type weixin struct{}

func (*weixin) Send(s string) error {
	fmt.Println("send weixin:", s)
	return nil
}

type email struct{}

func (*email) Send(s string) error {
	fmt.Println("send email:", s)
	return nil
}

type InfoMessage struct {
	method MessageMethod
}

func (i *InfoMessage) SendMessage(s string) error {
	s = "info message: " + s
	return i.method.Send(s)
}

type UrgencyMessage struct {
	method MessageMethod
}

func (u *UrgencyMessage) SendMessage(s string) error {
	s = "urgency message: " + s
	return u.method.Send(s)
}

func main() {
	qq := new(qq)
	weixin := new(weixin)
	email := new(email)

	info := new(InfoMessage)
	info.method = qq
	info.SendMessage("hello")

	info.method = weixin
	info.SendMessage("hello")

	info.method = email
	info.SendMessage("hello")

	urgency := new(UrgencyMessage)
	urgency.method = qq
	urgency.SendMessage("hello")

	urgency.method = weixin
	urgency.SendMessage("hello")

	urgency.method = email
	urgency.SendMessage("hello")
}
/*
send qq: info message: hello
send weixin: info message: hello
send email: info message: hello
send qq: urgency message: hello
send weixin: urgency message: hello
send email: urgency message: hello
*/
```

## 装饰器模式

装饰模式使用对象组合的方式动态改变或增加对象行为。Go语言借助于匿名组合和非入侵式接口可以很方便实现装饰模式。使用匿名组合，在装饰器中不必显式定义转调原对象方法。

### 代码实现

```go
package main

import "fmt"

type Component interface {
	Calc() int
}

type ConcreteComponent struct{}

func (*ConcreteComponent) Calc() int {
	return 10
}

type MulDecorator struct {
	Component
	num int
}

func WarpMulDecorator(c Component, num int) Component {
	return &MulDecorator{
		Component: c,
		num:       num,
	}
}

func (d *MulDecorator) Calc() int {
	return d.Component.Calc() * d.num
}

type AddDecorator struct {
	Component
	num int
}

func WarpAddDecorator(c Component, num int) Component {
	return &AddDecorator{
		Component: c,
		num:       num,
	}
}

func (d *AddDecorator) Calc() int {
	return d.Component.Calc() + d.num
}

func main() {
	c := &ConcreteComponent{}
	md := WarpMulDecorator(c, 2)
	ad := WarpAddDecorator(c, 3)
	fmt.Println(md.Calc())
	fmt.Println(ad.Calc())
}

/*
20
13
*/
```

## 代理模式

代理模式用于延迟处理操作或者在进行实际操作前后进行其它处理。比如在限流中间件中

### 代码实现

```go
package main

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

type Serve interface {
	handle(name string) (string, error)
}

type server struct {
	lock              sync.RWMutex
	serve             Serve
	maxAllowedRequest int
	rateLimiter       map[string]int
}

func (s *server) getService(name string) (string, error) {
	s.lock.RLock()
	nowNumber := s.rateLimiter[name]
	s.lock.RUnlock()
	if nowNumber >= s.maxAllowedRequest {
		return "", errors.New("rate limit")
	}

	// 更新计数器
	s.lock.Lock()
	s.rateLimiter[name]++
	s.lock.Unlock()

	str, err := s.serve.handle(name)
	// 执行后减少计数器
	s.lock.Lock()
	s.rateLimiter[name]--
	s.lock.Unlock()
	if err != nil {
		return "", err
	}
	return str, nil
}

type hand struct{}

func (h *hand) handle(name string) (string, error) {
	time.Sleep(time.Microsecond * 500)
	return fmt.Sprintf("hello %s", name), nil
}

func main() {
	wg := &sync.WaitGroup{}
	wg.Add(20)
	s := &server{
		serve:             &hand{},
		maxAllowedRequest: 10,
		rateLimiter:       map[string]int{},
	}
	for i := 0; i < 20; i++ {
		go func(i int) {
			defer wg.Done()
			res, err := s.getService("world")
			if err != nil {
				fmt.Println(i, "error:", err)
			} else {
				fmt.Println(i, "success:", res)
			}
		}(i)
	}
	wg.Wait()
}

/*
15 error: rate limit
18 error: rate limit
10 error: rate limit
4 error: rate limit
7 error: rate limit
6 error: rate limit
16 error: rate limit
9 error: rate limit
11 error: rate limit
17 error: rate limit
14 success: hello world
19 success: hello world
13 success: hello world
2 success: hello world
12 success: hello world
1 success: hello world
3 success: hello world
8 success: hello world
5 success: hello world
0 success: hello world
*/
```

## 组合模式

组合模式统一对象和对象集，使得使用相同接口使用对象和对象集。

组合模式常用于树状结构，用于统一叶子节点和树节点的访问，并且可以用于应用某一操作到所有子节点。

比如要搜索文件夹下的所有文件名

### 代码实现

```go
package main

import "fmt"

type component interface {
	search(string)
}

type file struct {
	name string
}

func (f *file) search(keyword string) {
	fmt.Printf("Searching for keyword %s in file %s\n", keyword, f.name)
}

func (f *file) getName() string {
	return f.name
}

type folder struct {
	components []component
	name       string
}

func (f *folder) search(keyword string) {
	fmt.Printf("Serching recursively for keyword %s in folder %s\n", keyword, f.name)
	for _, composite := range f.components {
		composite.search(keyword)
	}
}

func (f *folder) add(c component) {
	f.components = append(f.components, c)
}

func main() {
	file1 := &file{name: "File1"}
	file2 := &file{name: "File2"}
	file3 := &file{name: "File3"}

	folder1 := &folder{
		name: "Folder1",
	}

	folder1.add(file1)

	folder2 := &folder{
		name: "Folder2",
	}
	folder2.add(file2)
	folder2.add(file3)
	folder2.add(folder1)

	folder2.search("rose")
}
/*
Serching recursively for keyword rose in folder Folder2
Searching for keyword rose in file File2
Searching for keyword rose in file File3
Serching recursively for keyword rose in folder Folder1
Searching for keyword rose in file File1
*/
```

## 外观模式

API 为facade 模块的外观接口，大部分代码使用此接口简化对facade类的访问。

facade模块同时暴露了a和b 两个Module 的NewXXX和interface，其它代码如果需要使用细节功能时可以直接调用。

### 代码实现

```go
package main

import "fmt"

func NewAPI() API {
	return &apiImpl{
		a: NewAModuleAPI(),
		b: NewBModuleAPI(),
	}
}

//API is facade interface of facade package
type API interface {
	Test() string
}

//facade implement
type apiImpl struct {
	a AModuleAPI
	b BModuleAPI
}

func (a *apiImpl) Test() string {
	aRet := a.a.TestA()
	bRet := a.b.TestB()
	return fmt.Sprintf("%s\n%s", aRet, bRet)
}

//NewAModuleAPI return new AModuleAPI
func NewAModuleAPI() AModuleAPI {
	return &aModuleImpl{}
}

//AModuleAPI ...
type AModuleAPI interface {
	TestA() string
}

type aModuleImpl struct{}

func (*aModuleImpl) TestA() string {
	return "A module running"
}

//NewBModuleAPI return new BModuleAPI
func NewBModuleAPI() BModuleAPI {
	return &bModuleImpl{}
}

//BModuleAPI ...
type BModuleAPI interface {
	TestB() string
}

type bModuleImpl struct{}

func (*bModuleImpl) TestB() string {
	return "B module running"
}

func main() {
	api := NewAPI()
	fmt.Println(api.Test())
	
}
/*
A module running
B module running
*/
```

## 享元模式

享元模式从对象中剥离出不发生改变且多个实例需要的重复数据，独立出一个享元，使多个对象共享，从而节省内存以及减少对象数量。

### 代码实现

```go
package main

import "fmt"

type ImageFlyweightFactory struct {
	maps map[string]*ImageFlyweight
}

var imageFactory *ImageFlyweightFactory

func GetImageFlyweightFactory() *ImageFlyweightFactory {
	if imageFactory == nil {
		imageFactory = &ImageFlyweightFactory{
			maps: make(map[string]*ImageFlyweight),
		}
	}
	return imageFactory
}

func (f *ImageFlyweightFactory) Get(filename string) *ImageFlyweight {
	image := f.maps[filename]
	if image == nil {
		image = NewImageFlyweight(filename)
		f.maps[filename] = image
	}

	return image
}

type ImageFlyweight struct {
	data string
}

func NewImageFlyweight(filename string) *ImageFlyweight {
	// Load image file
	data := fmt.Sprintf("image data %s", filename)
	return &ImageFlyweight{
		data: data,
	}
}

func (i *ImageFlyweight) Data() string {
	return i.data
}

type ImageViewer struct {
	*ImageFlyweight
}

func NewImageViewer(filename string) *ImageViewer {
	image := GetImageFlyweightFactory().Get(filename)
	return &ImageViewer{
		ImageFlyweight: image,
	}
}

func (i *ImageViewer) Display() {
	fmt.Printf("Display: %s\n", i.Data())
}
```

## References

https://github.com/senghoo/golang-design-pattern

https://refactoringguru.cn/design-patterns

https://lailin.xyz/post/singleton.html
