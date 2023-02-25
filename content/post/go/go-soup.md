---
title: "Go HTML标签提取器soup"
date: 2020-10-31T12:52:33+08:00
draft: false
toc: true
categories: [go]
tags: [golang]
authors:
    - haiyux
---


## 什么是soup

类似python中beatifulsoup，用于提取html标签提取，多用于爬虫。它可以很好的处理不规范标记并生成剖析树(parse tree)。 它提供简单又常用的导航，搜索以及修改剖析树的操作。利用它我们不在需要编写正则表达式就可以方便的实现网页信息的提取。soup是一个小型的网页提取包，其接口与beauthoulsoup非常相似。

## 下载

```bash
go get github.com/anaskhan96/soup
```

## 接口

- var Headers map[string]string 将头文件设置为键-值对的映射，这是单独调用Header()的替代方法
- var Cookies map[string]string 将Cookie设置为键-值对的映射，这是单独调用Cookie()的另一种方法
- func Get(string) (string,error) {} 将url作为参数，返回HTML字符串
- func GetWithClient(string, *http.Client) {} 将url和自定义HTTP客户端作为参数，返回HTML字符串
- func Post(string, string, interface{}) (string, error) {} 以url、bodyType和负载为参数，返回HTML字符串
- func PostForm(string, url.Values) {} 接受url和正文。bodyType设置为“application/x-www-form-urlencoded
- func Header(string, string) {}  接受key，value对，将其设置为Get（）中的HTTP请求的头
- func Cookie(string, string) {} 接受key，value对，将其设置为要与Get（）中的HTTP请求一起发送的Cookie
- func HTMLParse(string) Root {} 以HTML字符串为参数，返回一个指向构造的DOM的指针
- func Find([]string) Root {} Element标记，（属性键值对）作为参数，返回指向第一个出现的指针
- func FindAll([]string) []Root {} 与Find（）相同，但返回指向所有匹配项的指针
- func FindStrict([]string) Root {}  Element tag，（attribute key-value pair）作为参数，指向第一次出现的指针返回了完全匹配的值
- func FindAllStrict([]string) []Root {} 与FindStrict（）相同，但指向返回的所有引用的指针
- func FindNextSibling() Root {} find指向同一个functing}元素的下一个functing}指针
- func FindNextElementSibling() Root {} 指向返回的DOM中元素的下一个同级元素的指针
- func FindPrevSibling() Root {} 指向返回的DOM中元素的上一个同级的指针
- func FindPrevElementSibling() Root {} 指向返回的DOM中元素的上一个同级元素的指针
- func Children() []Root {} 查找此DOM元素的所有直接子级
- func Attrs() map[string]string {} map返回元素的所有属性作为对其各自值的查找
- func Text() string {} 返回非嵌套标记内的全文，在嵌套标记中返回前半部分e
- func FullText() string {} 返回嵌套/非嵌套标记内的全文
- func SetDebug(bool) {}  将调试模式设置为true或false；默认为false
- func HTML() {}  HTML返回特定元素的HTML代码

## 例子

```go
package main

import (
	"fmt"
	"os"

	"github.com/anaskhan96/soup"
)

func main() {
	resp, err := soup.Get("https://zhaiyux.cc")
	if err != nil {
		os.Exit(1)
	}
	doc := soup.HTMLParse(resp)
	links := doc.Find("div", "class", "res-cons").FindAll("article","class","post")
	fmt.Println(links)
	for _, link := range links {
		l := link.Find("a")
		fmt.Println(l.Text(), "-------->", l.Attrs()["href"])
	}
}
```

结果

```
【置顶】golang目录 --------> https://zhaiyux.cc/post/go/go_catalog/
go语言文件系统 --------> https://zhaiyux.cc/post/go/go_file/
Flex --------> https://zhaiyux.cc/post/javascript/flex/
makefile --------> https://zhaiyux.cc/post/go/makefile/
air热加载 --------> https://zhaiyux.cc/post/go/air/
thrift的介绍及其使用 --------> https://zhaiyux.cc/post/go/thrift/
golang中间件的实现 --------> https://zhaiyux.cc/post/go/middleware/
zap高性能日志 --------> https://zhaiyux.cc/post/go/zap/
viper配置管理 --------> https://zhaiyux.cc/post/go/viper/
proto Prometheus --------> https://zhaiyux.cc/post/go/promethues/
```
