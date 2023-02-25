---
title: "Go Template"
date: 2020-10-21T17:26:32+08:00
draft: false
toc: true
categories: [go]
tags: [golang]
authors:
    - haiyux
---


## html模板生成:

*   html/template包实现了数据驱动的模板，用于生成可对抗代码注入的安全HTML输出。它提供了和text/template包相同的接口，Go语言中输出HTML的场景都应使用text/template包。

## 模板语法

### {{.}}

*   模板语法都包含在{{和}}中间，其中{{.}}中的点表示当前对象。

*   当我们传入一个结构体对象时，我们可以根据.来访问结构体的对应字段。例如：

```go
// main.go
func sayHello(w http.ResponseWriter, r *http.Request) {
    // 解析指定文件生成模板对象
    tmpl, err := template.ParseFiles("./hello.html")
    if err != nil {
        fmt.Println("create template failed, err:", err)
        return
    }
    var user = struct {
        name string
        age int
    }{
        name:"zhaohaiyu",
        age:18,
    }
    // 利用给定数据渲染模板，并将结果写入w
    tmpl.Execute(w, user)
}
func main() {
    http.HandleFunc("/", sayHello)
    err := http.ListenAndServe(":9090", nil)
    if err != nil {
        fmt.Println("HTTP server failed,err:", err)
        return
    }
}
``````


    Hello
    姓名 {{.Name}}
    年龄：{{.Age}}
    同理，当我们传入的变量是map时，也可以在模板文件中通过.根据key来取值。

### 注释

{{/* a comment */}}

### pipeline

*   pipeline是指产生数据的操作。比如{{.}}、{{.Name}}等。Go的模板语法中支持使用管道符号|链接多个命令，用法和unix下的管道类似：|前面的命令会将运算结果(或返回值)传递给后一个命令的最后一个位置。

**注意：**并不是只有使用了|才是pipeline。Go的模板语法中，pipeline的概念是传递数据，只要能产生数据的，都是pipeline。

### 变量

*   我们还可以在模板中声明变量，用来保存传入模板的数据或其他语句生成的结果。具体语法如下：

```go
$obj := {{.}}

其中$obj是变量的名字，在后续的代码中就可以使用该变量了。
```

### 移除空格

*   有时候我们在使用模板语法的时候会不可避免的引入一下空格或者换行符，这样模板最终渲染出来的内容可能就和我们想的不一样，这个时候可以使用{{-语法去除模板内容左侧的所有空白符号， 使用-}}去除模板内容右侧的所有空白符号。

例如：{{- .Name -}}

**注意：**-要紧挨{{和}}，同时与模板值之间需要使用空格分隔。

### 条件判断

*   Go模板语法中的条件判断有以下几种:

```go
{{if pipeline}} T1 {{end}}
{{if pipeline}} T1 {{else}} T0 {{end}}
{{if pipeline}} T1 {{else if pipeline}} T0 {{end}}
```

### range

Go的模板语法中使用range关键字进行遍历，有以下两种写法，其中pipeline的值必须是数组、切片、字典或者通道。

```go
{{range pipeline}} T1 {{end}}

{{range pipeline}} T1 {{else}} T0 {{end}}
```

### with

```go
{{with pipeline}} T1 {{end}}

{{with pipeline}} T1 {{else}} T0 {{end}}
```



### 预定义函数

执行模板时，函数从两个函数字典中查找：首先是模板函数字典，然后是全局函数字典。一般不在模板内定义函数，而是使用Funcs方法添加函数到模板里。

预定义的全局函数如下：

1.  and
    *   函数返回它的第一个empty参数或者最后一个参数；
    *   就是说"and x y"等价于"if x then y else x"；所有参数都会执行；
2.  or
    *   返回第一个非empty参数或者最后一个参数；
    *   亦即"or x y"等价于"if x then x else y"；所有参数都会执行；
3.  not
    *   返回它的单个参数的布尔值的否定
4.  len
    *   返回它的参数的整数类型长度
5.  index
    *   执行结果为第一个参数以剩下的参数为索引/键指向的值；
    *   如"index x 1 2 3"返回x[1][2][3]的值；每个被索引的主体必须是数组、切片或者字典。
6.  print
    *   即fmt.Sprint
7.  printf
    *   即fmt.Sprintf
8.  println
    *   即fmt.Sprintln
9.  html
    *   返回与其参数的文本表示形式等效的转义HTML。
    *   这个函数在html/template中不可用。
10.  urlquery

*   以适合嵌入到网址查询中的形式返回其参数的文本表示的转义值。
*   这个函数在html/template中不可用。

1.  js

*   返回与其参数的文本表示形式等效的转义JavaScript。

1.  call

*   执行结果是调用第一个参数的返回值，该参数必须是函数类型，其余参数作为调用该函数的参数；

    如"call .X.Y 1 2"等价于go语言里的dot.X.Y(1, 2)；
    其中Y是函数类型的字段或者字典的值，或者其他类似情况；
    call的第一个参数的执行结果必须是函数类型的值（和预定义函数如print明显不同）；
    该函数类型值必须有1到2个返回值，如果有2个则后一个必须是error接口类型；
    如果有2个返回值的方法返回的error非nil，模板执行会中断并返回给调用模板执行者该错误；

### 比较函数

*   布尔函数会将任何类型的零值视为假，其余视为真。

下面是定义为函数的二元比较运算的集合：

eq      如果arg1 == arg2则返回真
ne      如果arg1 != arg2则返回真
lt      如果arg1 < arg2则返回真
le      如果arg1 <= arg2则返回真
gt      如果arg1 > arg2则返回真
ge      如果arg1 >= arg2则返回真

为了简化多参数相等检测，eq（只有eq）可以接受2个或更多个参数，它会将第一个参数和其余参数依次比较，返回下式的结果：

{{eq arg1 arg2 arg3}}

比较函数只适用于基本类型（或重定义的基本类型，如”type Celsius float32”）。但是，整数和浮点数不能互相比较。

### 自定义函数

Go的模板支持自定义函数。

```go
func sayHello(w http.ResponseWriter, r *http.Request) {
	htmlByte, err := ioutil.ReadFile("./hello.tmpl")
	if err != nil {
		fmt.Println("read html failed, err:", err)
		return
	}
	// 自定义一个夸人的模板函数
	kua := func(arg string) (string, error) {
		return arg + "真帅", nil
	}
	// 采用链式操作在Parse之前调用Funcs添加自定义的kua函数
	tmpl, err := template.New("hello").Funcs(template.FuncMap{"kua": kua}).Parse(string(htmlByte))
	if err != nil {
		fmt.Println("create template failed, err:", err)
		return
	}
	user := UserInfo{
		Name:   "小王子",
		Gender: "男",
		Age:    18,
	}
	// 使用user渲染模板，并将结果写入w
	tmpl.Execute(w, user)
}
```

我们可以在模板文件hello.tmpl中按照如下方式使用我们自定义的kua函数了。

{{kua .Name}}
### 嵌套template

我们可以在template中嵌套其他的template。这个template可以是单独的文件，也可以是通过define定义的template。

举个例子：t.tmpl文件内容如下：tmpl test

测试嵌套template语法 {{template "ul.tmpl"}}

    {{template "ol.tmpl"}}
    
    {{ define "ol.tmpl"}}
    吃饭
    睡觉
    打豆豆
    {{end}}

ul.tmpl文件内容如下：
注释
日志
测试
我们注册一个templDemo路由处理函数.
http.HandleFunc("/tmpl", tmplDemo)
tmplDemo函数的具体内容如下：

```go
func tmplDemo(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("./t.tmpl", "./ul.tmpl")
	if err != nil {
		fmt.Println("create template failed, err:", err)
		return
	}
	user := UserInfo{
		Name:   "小王子",
		Gender: "男",
		Age:    18,
	}
	tmpl.Execute(w, user)
}
```

**注意**：在解析模板时，被嵌套的模板一定要在后面解析，例如上面的示例中t.tmpl模板中嵌套了ul.tmpl，所以ul.tmpl要在t.tmpl后进行解析。

### block

{{block "name" pipeline}} T1 {{end}}

block是定义模板{{define "name"}} T1 {{end}}和执行{{template "name" pipeline}}缩写，典型的用法是定义一组根模板，然后通过在其中重新定义块模板进行自定义。

定义一个根模板templates/base.tmpl，内容如下：Go Templates

{{block "content" . }}{{end}}

然后定义一个templates/index.tmpl，”继承”base.tmpl：

```go
{{template "base.tmpl"}}
{{define "content"}}
    Hello world!
{{end}}
```

然后使用template.ParseGlob按照正则匹配规则解析模板文件，然后通过ExecuteTemplate渲染指定的模板：

```go
func index(w http.ResponseWriter, r *http.Request){
	tmpl, err := template.ParseGlob("templates/*.tmpl")
	if err != nil {
		fmt.Println("create template failed, err:", err)
		return
	}
	err = tmpl.ExecuteTemplate(w, "index.tmpl", nil)
	if err != nil {
		fmt.Println("render template failed, err:", err)
		return
	}
}
```

如果我们的模板名称冲突了，例如不同业务线下都定义了一个index.tmpl模板，我们可以通过下面两种方法来解决。

1.  在模板文件开头使用{{define 模板名}}语句显式的为模板命名。
2.  可以把模板文件存放在templates文件夹下面的不同目录中，然后使用template.ParseGlob("templates/**/*.tmpl")解析模板。

### 修改默认的标识符

Go标准库的模板引擎使用的花括号{{和}}作为标识，而许多前端框架（如Vue和AngularJS）也使用{{和}}作为标识符，所以当我们同时使用Go语言模板引擎和以上前端框架时就会出现冲突，这个时候我们需要修改标识符，修改前端的或者修改Go语言的。这里演示如何修改Go语言模板引擎默认的标识符：

template.New("test").Delims("{[", "]}").ParseFiles("./t.tmpl")
## text/template与html/tempalte的区别

html/template针对的是需要返回HTML内容的场景，在模板渲染过程中会对一些有风险的内容进行转义，以此来防范跨站脚本攻击。

例如，我定义下面的模板文件：


```go
Hello
{{.}}
```

这个时候传入一段JS代码并使用html/template去渲染该文件，会在页面上显示出转义后的JS内容。alert('嘿嘿嘿')这就是html/template为我们做的事。

但是在某些场景下，我们如果相信用户输入的内容，不想转义的话，可以自行编写一个safe函数，手动返回一个template.HTML类型的内容。示例如下：

```go
func xss(w http.ResponseWriter, r *http.Request){
	tmpl,err := template.New("xss.tmpl").Funcs(template.FuncMap{
		"safe": func(s string)template.HTML {
			return template.HTML(s)
		},
	}).ParseFiles("./xss.tmpl")
	if err != nil {
		fmt.Println("create template failed, err:", err)
		return
	}
	jsStr := `alert('嘿嘿嘿')`
	err = tmpl.Execute(w, jsStr)
	if err != nil {
		fmt.Println(err)
	}
}
```

这样我们只需要在模板文件不需要转义的内容后面使用我们定义好的safe函数就可以了。{{ . | safe }}

## 代码生成

**生成代码用text/template包,模板语法和html/template一样**

```go
package main
import (
	"fmt"
	"html/template"
	"os"
)
var data = `
package main
import "fmt"
func main() {
	str := "{{ . }}"
	for _, v := range str {
		fmt.Println(v)
	}
}
`
func main() {
	t := template.New("main")
	t, err := t.Parse(data)
	if err != nil {
		fmt.Println("解析失败")
		return
	}
	var str = "zhaohaiyu"
	file, err := os.OpenFile("./print/main.go", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		fmt.Printf("open file:%s failed, err:%v\n", "./print/main.go", err)
		return
	}
	err = t.Execute(file, str)
	if err != nil {
		fmt.Println("execute failed err:",err)
		return
	}
	return
}
```

生成的代码:

```go
package main
import "fmt"
func main() {
	str := "zhaohaiyu"
	for _, v := range str {
		fmt.Println(v)
	}
}
```

参考文章:

*   [https://www.liwenzhou.com/posts/Go/go_template/#autoid-1-3-0](https://www.liwenzhou.com/posts/Go/go_template/#autoid-1-3-0)