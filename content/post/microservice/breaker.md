---
title: "从kratos分析breaker熔断器源码实现"
date: 2021-09-04T17:55:01+08:00
draft: false
toc: true
categories: [microservice,go]
authors:
    - haiyux
---

## 为什么要用熔断

前面我们讲过限流保证服务的可用性，不被突如其来的流量打爆。但是两种情况是限流解决不了的。

1. 如果我们服务只能处理1000QPS，但是有10wQPS打过来，服务还是会炸。因为拒绝请求也需要成本。
2. 服务但是io型的，会把mysql，redis，mq等中间件打挂。

所以，我们遵循一个思路，可不可以client端在失败的多的时候就不调用了，直接返回错误呢？

## 什么是熔断

熔断器是为了当依赖的服务已经出现故障时，主动阻止对依赖服务的请求。保证自身服务的正常运行不受依赖服务影响，防止雪崩效应。

## 源码分析

### 源码地址

- https://github.com/go-kratos/aegis/tree/main/circuitbreaker

### CircuitBreaker 接口 

```go
type CircuitBreaker interface {
	Allow() error
	MarkSuccess()
	MarkFailed()
}
```

1. Allow() 
   - 判断熔断器是否允许通过
2. MarkSuccess()
   - 熔断器成功的回调
3. MarkFailed()
   - 熔断器失败的回调

### Group 结构体

```go
type Group struct {
   mutex sync.Mutex
   val   atomic.Value

   New func() CircuitBreaker
}
```

1. `mutex`
   - 互斥锁，使val这个map不产生数据竞争
2. `val`
   - map，存储name -> CircuitBreaker
3. `New`
   - 生成一个CircuitBreaker

#### Get方法

```go
// Get .
func (g *Group) Get(name string) CircuitBreaker {
	m, ok := g.val.Load().(map[string]CircuitBreaker)
	if ok {
		breaker, ok := m[name]
		if ok {
			return breaker // 很具name从val拿出 breaker 如果存在返回
		}
	}
	// slowpath for group don`t have specified name breaker.
	g.mutex.Lock()
	nm := make(map[string]CircuitBreaker, len(m)+1)
	for k, v := range m {
		nm[k] = v
	}
	breaker := g.New()
	nm[name] = breaker // 如果不存在 生成一个 并放入map 并返回
	g.val.Store(nm)
	g.mutex.Unlock()
	return breaker
}
```

### Breaker 结构体

```go
// Breaker is a sre CircuitBreaker pattern.
type Breaker struct {
   stat window.RollingCounter
   r    *rand.Rand
   // rand.New(...) returns a non thread safe object
   randLock sync.Mutex

   // Reducing the k will make adaptive throttling behave more aggressively,
   // Increasing the k will make adaptive throttling behave less aggressively.
   k       float64
   request int64

   state int32
}
```

1. stat
   - 滑动窗口，记录成功失败
2. r
   - 随机数
3. randLock
   - 读写锁
4. k 成功系数
   - total(总数) = success * k
5. request 请求数
   - 当总数 < request时，不判断是否熔断
6. state
   - 熔断器状态 打开或者关闭

### Allow()方法

```go
// Allow request if error returns nil.
func (b *Breaker) Allow() error {
	success, total := b.summary() // 从活动窗口获取成功数和总数
	k := b.k * float64(success) // 根据k成功系数 获取

	// check overflow requests = K * success
	if total < b.request || float64(total) < k { // 如果总数<request 或者  总数 < k 
		if atomic.LoadInt32(&b.state) == StateOpen { 
			atomic.CompareAndSwapInt32(&b.state, StateOpen, StateClosed) // 如果state是打开 关闭
		}
		return nil
	}
	if atomic.LoadInt32(&b.state) == StateClosed { 
		atomic.CompareAndSwapInt32(&b.state, StateClosed, StateOpen) // 如果state是关闭 打开
	}
	dr := math.Max(0, (float64(total)-k)/float64(total+1)) // 获取系数，当k越大 dr越小
	drop := b.trueOnProba(dr)
	// trueOnProba 获取水机数
  // 返回是否<dr
  
	if drop { // 如果是 拒绝请求
		return circuitbreaker.ErrNotAllowed
	}
	return nil
}

func (b *Breaker) trueOnProba(proba float64) (truth bool) {
	b.randLock.Lock()
	truth = b.r.Float64() < proba
	b.randLock.Unlock()
	return
}
```

使用trueOnProba的原因是，当熔断器关闭时，随机让一部分请求通过，当success越大，请求的通过的数量就越多。用这些数据成功与否，放入窗口统计，当成功数达到要求时，就可以关闭熔断器了。

### MarkSuccess()以及MarkFailed()方法

```go
// MarkSuccess mark requeest is success.
func (b *Breaker) MarkSuccess() {
	b.stat.Add(1) // 成功数+1
}

// MarkFailed mark request is failed.
func (b *Breaker) MarkFailed() {
	// NOTE: when client reject requets locally, continue add counter let the
	// drop ratio higher.
	b.stat.Add(0) // 失败数+1
}
```

## 流程图

![](/images/2344773-20210905222901516-230813200.png)

---

![](/images/2344773-20210902225224456-315933124.png)

![](/images/2344773-20210902225203602-1750987546.gif)
