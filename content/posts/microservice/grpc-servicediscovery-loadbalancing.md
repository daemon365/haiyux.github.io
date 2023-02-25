---
title: "grpc服务发现与负载均衡"
date: 2021-05-23T15:13:11+08:00
draft: false
toc: true
categories: [microservice]
tags: [微服务,protobuf,grpc]
authors:
    - haiyux
---

## 前言

   在后台服务开发中，高可用性是构建中核心且重要的一环。服务发现（Service discovery）和负载均衡（Load Balance）一直都是我关注的话题。今天来谈一下我在实际中是如何理解及落地的。

## 负载均衡 && 服务发现

#### 基础

   负载均衡 ，顾名思义，是通过某种手段将流量 / 请求分配到不通的服务器上去，保证后台的每个服务收到的请求都尽可能保持平衡
   服务发现 ，就是指客户端按照某种约定的方式主动去（注册中心）寻找服务，然后再连接相应的服务
   关于负载均衡的构建与实现，可以看下这几篇文章：

- [gRPC 服务发现 & 负载均衡](https://segmentfault.com/a/1190000008672912)
- [gRPC Load Balancing](https://grpc.io/blog/loadbalancing/)
- [Load Balancing in gRPC](https://github.com/grpc/grpc/blob/master/doc/load-balancing.md)

#### 服务发现概念

   我们说的服务发现，一般理解为客户端如何发现 (并连接到) 服务，这里一般包含三个组件：

1. 服务消费者：一般指客户端（可以是简单的 TCP-Client 或者是 RPC-Client ）
2. 服务提供者：一般指服务提供方，如传统服务，微服务等
3. 服务注册中心：用来存储（Key-Value）服务提供者的服务，一般以 DNS/HTTP/RPC 等方式对外暴露接口

#### 负载均衡概念

我们把 LB 看作一个组件，根据组件位置的不同，大致上分为三种：

#### 集中式 LB（Proxy Model）

   独立的 LB, 可以是硬件实现，如 F5，或者是 nginx 这种内置 Proxy-pass 或者 upstream 功能的网关，亦或是 LVS/HAPROXY，之前也使用 [DPDK](http://core.dpdk.org/doc/quick-start/) 开发过类似的专用网关。

![](/images/2344773-20210823145642439-214576130.png)

#### 进程内 LB（Balancing-aware Client）

   进程内 LB（集成到客户端），此方案将 LB 的功能集成到服务消费方进程里，也被称为软负载或者客户端负载方案。服务提供方启动时，首先将服务地址注册到服务注册表，同时定期报心跳到服务注册表以表明服务的存活状态，相当于健康检查，服务消费方要访问某个服务时，它通过内置的 LB 组件向服务注册表查询，同时缓存并定期刷新目标服务地址列表，然后以某种负载均衡策略选择一个目标服务地址，最后向目标服务发起请求。LB 和服务发现能力被分散到每一个服务消费者的进程内部，同时服务消费方和服务提供方之间是直接调用，没有额外开销，性能比较好。

![](/images/2344773-20210823145656926-9574896.png)

#### 独立 LB 进程（External Load Balancing Service）

   该方案是针对上一种方案的不足而提出的一种折中方案，原理和第二种方案基本类似。不同之处是将 LB 和服务发现功能从进程内移出来，变成主机上的一个独立进程。主机上的一个或者多个服务要访问目标服务时，他们都通过同一主机上的独立 LB 进程做服务发现和负载均衡。该方案也是一种分布式方案没有单点问题，一个 LB 进程挂了只影响该主机上的服务调用方，服务调用方和 LB 之间是进程内调用性能好，同时该方案还简化了服务调用方，不需要为不同语言开发客户库，LB 的升级不需要服务调用方改代码。 公司的 L5 是这种方式，每台机器上都安装了 L5 的 agent，供其他服务调用。该方案主要问题：部署较复杂，环节多，出错调试排查问题不方便。

![](/images/2344773-20210823145723217-284699775.png)

### gRPC 内置的方案

  gRPC 的内置方案如下图所示：

![](/images/2344773-20210823145734432-349821484.png)

gRPC 在官网文档中提供了实现 LB 的思路，并在不同语言的 gRPC 代码 API 中已提供了命名解析和负载均衡接口供扩展。默认提供了 DNS-resolver 的实现，接口相当规范，实现起来也不复杂，只需要实现服务注册（Registry）和服务监听 + 解析（Watcher+Resolver）的逻辑就行了，这里简单介绍其基本实现过程：

1. 构建注册中心，这里注册中心一般要求具备分布式一致性（满足 CAP 定理的 AP 或 CP）的高可用的组件集群，如 Zookeeper、Consul、Etcd 等
2. 构建 gRPC 服务端的注册逻辑，服务启动后定时向注册中心注册自身的关键信息（一般开启新的 groutine 来完成），至少包含 IP 和端口，其他可选信息，如自身的负载信息（CPU 和 Memory）、当前实时连接数等，这些辅助信息有助于帮助系统更好的执行 LB 算法
3. gRPC 客户端向注册中心发出服务解析请求，注册中心将请求中关联的所有服务的信息返回给 gRPC 客户端，客户端与所有在线的服务建立起 HTTP2 长连接
4. gRPC 客户端发起 RPC 调用，根据 LB 均衡器中实现的负载均衡策略（gRPC 中默认提供的算法是 RoundRobin），选择其中一 HTTP2 长连接进行通信，即 LB 策略决定哪个子通道 - 即哪个 gRPC 服务器将接收请求

## gRPC 负载均衡的运行机制

gRPC 提供了负载均衡实现的用户侧接口，我们可以非常方便的定制化业务的负载均衡策略，为了理解 gRPC 的负载均衡的实现机制，后续博客中我会分析下 `gRPC` 实现负载均衡的代码。

![](/images/2344773-20210823145800184-646304152.png)

1. Resolver
   - 解析器，用于从注册中心实时获取当前服务端的列表，同步发送给 Balancer
2. Balancer
   - 平衡器，一是接收从 Resolver 发送的服务端列表，建立并维护（长）连接状态；二是每次当 Client 发起 Rpc 调用时，按照一定算法从连接池中选择一个连接进行 Rpc 调用
3. Register
   - 注册，用于服务端初始化和在线时，将自己信息上报到注册中心，主要信息有 Ip，端口等

## 负载均衡的算法及实现

在实践中，如何选取负载均衡策略是一个很有趣的话题，例如 Nginx 的 `upstream` 机制中就有很多经典的 LB 策略，如带权重的轮询 [Weight-RoundRobin](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_upstream_round_robin.c)，一般常用的负载均衡方法有如下几种：

1. RoundRobin（轮询）
2. Weight-RoundRobin（加权轮询）
   - 不同的后端服务器可能机器的配置和当前系统的负载并不相同，因此它们的抗压能力也不相同。给配置高、负载低的机器配置更高的权重，而配置低、负载高的机器，给其分配较低的权重，降低其系统负载，加权轮询能很好地处理这一问题，并将请求顺序且按照权重分配到后端。
3. Random（随机）
4. Weight-Random（加权随机）
   - 通过系统的随机算法，根据后端服务器的列表随机选取其中的一台服务器进行访问
5. 源地址哈希法
   - 源地址哈希的思想是根据获取客户端的 IP 地址，通过哈希函数计算得到的一个数值，用该数值对服务器列表的大小进行取模运算，得到的结果便是客服端要访问服务器的序号。采用源地址哈希法进行负载均衡，同一 IP 地址的客户端，当后端服务器列表不变时，它每次都会映射到同一台后端服务器进行访问
6. 最小连接数法
   - 最小连接数算法比较灵活和智能，由于后端服务器的配置不尽相同，对于请求的处理有快有慢，它是根据后端服务器当前的连接情况，动态地选取其中当前积压连接数最少的一台服务器来处理当前的请求，尽可能地提高后端服务的利用效率，将负责合理地分流到每一台服务器
7. 一致性哈希算法
   - 常见的是 `Ketama` 算法，该算法是用来解决 `cache` 失效导致的缓存穿透的问题的，当然也可以适用于 gRPC 长连接的场景

## gRPC 服务治理的优势

   在现网环境中，后端服务就是采用了 gRPC 与 Etcd 的服务治理方案，总结下有这么几个优点；

- 采用了 gRPC 实现负载均衡策略，模块之间通信采用长连接方式，避免每次 RPC 调用时新建连接的开销，充分发挥 `HTTP2` 的优势
- 扩容和缩容都及其方便，例如扩容，只要部署上服务，运行后，服务成功注册到 Etcd 便大功告成
- 灵活的自定义的 LB 算法，使得后端压力更为均衡
- 客户端加入重试逻辑，使得网络抖动情况下，可以通过重试连接上另外一台服务

## Resolver 暴露的三个接口

前文说过，gRPC 内置的服务治理功能，对开发者暴露了服务发现的 `interface{}`，`resolver.Builder` 和 `resolver.ClientConn` 和 `resolver.Resolver`，[相关代码](https://github.com/grpc/grpc-go/blob/master/resolver/resolver.go)。开发者在实例化这三个接口之后，就可以实现从指定的 scheme 中获取服务列表，通知 balancer 并与这些服务端建立 RPC 长连接。

1. resolver.Builder
2. resolver.ClientConn
3. resolver.Resolver

- resolver.Builder `Builder` 用于 gRPC 内部创建 `Resolver` 接口的实现，但注意内部声明的 `Build()` 方法将接口 `ClientConn` 作为参数传入了，在前文的分析中，我们了解到 `ClientConn`[结库](https://github.com/grpc/grpc-go/blob/master/clientconn.go#L459) 是非常重要的结构，其成员 `conns map[*addrConn]struct{}` 中维护了所有从注册中心获取到的服务端列表。

```go
// Builder creates a resolver that will be used to watch name resolution updates.
type Builder interface {
// Build creates a new resolver for the given target.
//
// gRPC dial calls Build synchronously, and fails if the returned error is
// not nil.
Build(target Target, cc ClientConn, opts BuildOption) (Resolver, error)
// Scheme returns the scheme supported by this resolver.
// Scheme is defined at https://github.com/grpc/grpc/blob/master/doc/naming.md.
Scheme() string
}
```

- [resolver.ClientConn](https://github.com/grpc/grpc-go/blob/master/clientconn.go#L459) `ClientConn` 接口中，`UpdateState` 方法需要传入 `State` 结构，`NewAddress` 方法需要传入 `Address` 结构，看代码可以发现其中包含了 `Addresses []Address // Resolved addresses for the target`，可以看出是需要将服务发现得到的 `Address` 对象列表告诉 `ClientConn` 的对象。

```go
// ClientConn contains the callbacks for resolver to notify any updates
// to the gRPC ClientConn.
//
// This interface is to be implemented by gRPC. Users should not need a
// brand new implementation of this interface. For the situations like
// testing, the new implementation should embed this interface. This allows
// gRPC to add new methods to this interface.
type ClientConn interface {
// UpdateState updates the state of the ClientConn appropriately.
UpdateState(State)
// NewAddress is called by resolver to notify ClientConn a new list
// of resolved addresses.
// The address list should be the complete list of resolved addresses.
//
// Deprecated: Use UpdateState instead.
NewAddress(addresses []Address)
// NewServiceConfig is called by resolver to notify ClientConn a new
// service config. The service config should be provided as a json string.
//
// Deprecated: Use UpdateState instead.
NewServiceConfig(serviceConfig string)
}
```

- resolver.Resolver `Resolver` 提供了 `ResolveNow` 用于被 gRPC 尝试重新进行服务发现

```go
// Resolver watches for the updates on the specified target.
// Updates include address updates and service config updates.
type Resolver interface {
// ResolveNow will be called by gRPC to try to resolve the target name
// again. It's just a hint, resolver can ignore this if it's not necessary.
//
// It could be called multiple times concurrently.
ResolveNow(ResolveNowOption)
// Close closes the resolver.
Close()
}
```

## 梳理 Resolver 过程

通过这三个接口，再次梳理下 gRPC 的服务发现实现逻辑

1. 通过 `Builder.Build()` 进行 `Reslover` 的创建，在 `Build()` 的过程中将服务发现的地址信息丢给 `ClientConn` 用于内部连接创建（通过 `ClientConn.UpdateState()` 实现）等逻辑；
2. 当 `client` 在 `Dial` 时会根据 `target` 解析的 `scheme` 获取对应的 `Builder`，[代码位置](https://github.com/grpc/grpc-go/blob/master/clientconn.go#L242)

```go
func DialContext(ctx context.Context, target string, opts ...DialOption) (conn *ClientConn, err error) {
...
...
// Determine the resolver to use.
cc.parsedTarget = parseTarget(cc.target)
grpclog.Infof("parsed scheme: %q", cc.parsedTarget.Scheme)
resolverBuilder := cc.getResolver(cc.parsedTarget.Scheme)		// 通过 scheme(名字) 获取对应的 resolver
if resolverBuilder == nil {
    // If resolver builder is still nil, the parsed target's scheme is
    // not registered. Fallback to default resolver and set Endpoint to
    // the original target.
    grpclog.Infof("scheme %q not registered, fallback to default scheme", cc.parsedTarget.Scheme)
    cc.parsedTarget = resolver.Target{
        Scheme:   resolver.GetDefaultScheme(),
        Endpoint: target,
    }
    resolverBuilder = cc.getResolver(cc.parsedTarget.Scheme)
    if resolverBuilder == nil {
        return nil, fmt.Errorf("could not get resolver for default scheme: %q", cc.parsedTarget.Scheme)
    }
}
...
...
// Build the resolver.
rWrapper, err := newCCResolverWrapper(cc, resolverBuilder)		// 通过 gRPC 提供的 Wrapper，应用我们实现的 resolver 逻辑
if err != nil {
    return nil, fmt.Errorf("failed to build resolver: %v", err)
}
cc.mu.Lock()
cc.resolverWrapper = rWrapper
cc.mu.Unlock()
...
...
}
```

3. 当 `Dial` 成功会创建出结构体 `ClientConn` 的对象 [官方代码位置](https://github.com/grpc/grpc-go/blob/master/clientconn.go#L447)(注意不是上面的 `ClientConn` 接口)，可以看到结构体 `ClientConn` 内的成员 `resolverWrapper` 又实现了接口 `ClientConn` 的方法 [官方代码位置](https://github.com/grpc/grpc-go/blob/master/resolver_conn_wrapper.go)

```go
func DialContext(ctx context.Context, target string, opts ...DialOption) (conn *ClientConn, err error) {
// 初始化 CC
cc := &ClientConn{
    target:            target,
    csMgr:             &connectivityStateManager{},
    conns:             make(map[*addrConn]struct{}),
    dopts:             defaultDialOptions(),
    blockingpicker:    newPickerWrapper(),
    czData:            new(channelzData),
    firstResolveEvent: grpcsync.NewEvent(),
}
...
...

...
...
return cc, nil
}
```

4. 当 `resolverWrapper` 被初始化时就会调用 `Build` 方法 [官方代码位置](https://github.com/grpc/grpc-go/blob/master/resolver_conn_wrapper.go#L89)，其中参数为接口 `ClientConn` 传入的是 `ccResolverWrapper`

```go
// newCCResolverWrapper uses the resolver.Builder to build a Resolver and
// returns a ccResolverWrapper object which wraps the newly built resolver.
func newCCResolverWrapper(cc *ClientConn, rb resolver.Builder) (*ccResolverWrapper, error) {
ccr := &ccResolverWrapper{
    cc:   cc,
    done: grpcsync.NewEvent(),
}

var credsClone credentials.TransportCredentials
if creds := cc.dopts.copts.TransportCredentials; creds != nil {
    credsClone = creds.Clone()
}
rbo := resolver.BuildOptions{
    DisableServiceConfig: cc.dopts.disableServiceConfig,
    DialCreds:            credsClone,
    CredsBundle:          cc.dopts.copts.CredsBundle,
    Dialer:               cc.dopts.copts.Dialer,
}

var err error
// We need to hold the lock here while we assign to the ccr.resolver field
// to guard against a data race caused by the following code path,
// rb.Build-->ccr.ReportError-->ccr.poll-->ccr.resolveNow, would end up
// accessing ccr.resolver which is being assigned here.
ccr.resolverMu.Lock()
defer ccr.resolverMu.Unlock()
ccr.resolver, err = rb.Build(cc.parsedTarget, ccr, rbo)
if err != nil {
    return nil, err
}
return ccr, nil
}
```

5. 当用户基于 `Builder` 的实现进行 `UpdateState` 调用时，则会触发结构体 `ClientConn` 的 `updateResolverState` 方法 [官方代码位置](https://github.com/grpc/grpc-go/blob/master/resolver_conn_wrapper.go#L109)，`updateResolverState` 则会对传入的 `Address` 进行初始化等逻辑 [官方代码位置](https://github.com/grpc/grpc-go/blob/master/clientconn.go#L553)

```go
func (cc *ClientConn) updateResolverState(s resolver.State, err error) error {
defer cc.firstResolveEvent.Fire()
cc.mu.Lock()
// Check if the ClientConn is already closed. Some fields (e.g.
// balancerWrapper) are set to nil when closing the ClientConn, and could
// cause nil pointer panic if we don't have this check.
if cc.conns == nil {
    cc.mu.Unlock()
    return nil
}

if err != nil {
    // May need to apply the initial service config in case the resolver
    // doesn't support service configs, or doesn't provide a service config
    // with the new addresses.
    cc.maybeApplyDefaultServiceConfig(nil)

    if cc.balancerWrapper != nil {
        cc.balancerWrapper.resolverError(err)
    }

    // No addresses are valid with err set; return early.
    cc.mu.Unlock()
    return balancer.ErrBadResolverState
}

var ret error
if cc.dopts.disableServiceConfig || s.ServiceConfig == nil {
    cc.maybeApplyDefaultServiceConfig(s.Addresses)
    // TODO: do we need to apply a failing LB policy if there is no
    // default, per the error handling design?
} else {
    if sc, ok := s.ServiceConfig.Config.(*ServiceConfig); s.ServiceConfig.Err == nil && ok {
        cc.applyServiceConfigAndBalancer(sc, s.Addresses)
    } else {
        ret = balancer.ErrBadResolverState
        if cc.balancerWrapper == nil {
            var err error
            if s.ServiceConfig.Err != nil {
                err = status.Errorf(codes.Unavailable, "error parsing service config: %v", s.ServiceConfig.Err)
            } else {
                err = status.Errorf(codes.Unavailable, "illegal service config type: %T", s.ServiceConfig.Config)
            }
            cc.blockingpicker.updatePicker(base.NewErrPicker(err))
            cc.csMgr.updateState(connectivity.TransientFailure)
            cc.mu.Unlock()
            return ret
        }
    }
}

var balCfg serviceconfig.LoadBalancingConfig
if cc.dopts.balancerBuilder == nil && cc.sc != nil && cc.sc.lbConfig != nil {
    balCfg = cc.sc.lbConfig.cfg
}

cbn := cc.curBalancerName
bw := cc.balancerWrapper
cc.mu.Unlock()
if cbn != grpclbName {
    // Filter any grpclb addresses since we don't have the grpclb balancer.
    for i := 0; i <len(s.Addresses); {
        if s.Addresses[i].Type == resolver.GRPCLB {
            copy(s.Addresses[i:], s.Addresses[i+1:])
            s.Addresses = s.Addresses[:len(s.Addresses)-1]
            continue
        }
        i++
    }
}
uccsErr := bw.updateClientConnState(&balancer.ClientConnState{ResolverState: s, BalancerConfig: balCfg})
if ret == nil {
    ret = uccsErr // prefer ErrBadResolver state since any other error is
    // currently meaningless to the caller.
}
return ret
}
```

6. 至此整个服务发现过程就结束了。从中也可以看出 gRPC 官方提供的三个接口还是很灵活的，但也正因为灵活要实现稍微麻烦一些，而 `Address`[官方代码位置](https://github.com/grpc/grpc-go/blob/master/resolver/resolver.go#L79) 如果直接被业务拿来用于服务节点信息的描述结构则显得有些过于简单。

所以 `warden` 包装了 gRPC 的整个服务发现实现逻辑，代码分别位于 `pkg/naming/naming.go` 和 `warden/resolver/resolver.go`，其中：

- `naming.go` 内定义了用于描述业务实例的 `Instance` 结构、用于服务注册的 `Registry` 接口、用于服务发现的 `Resolver` 接口
- `resolver.go` 内实现了 gRPC 官方的 `resolver.Builder` 和 `resolver.Resolver` 接口，但也暴露了 `naming.go` 内的 `naming.Builder` 和 `naming.Resolver` 接口



## 文章转自：

- [基于 gRPC 的服务发现与负载均衡（基础篇） - 熊喵君的博客 | PANDAYCHEN](https://pandaychen.github.io/2019/07/11/GRPC-SERVICE-DISCOVERY/)
- [gRPC 应用篇之 Resolver 接口封装 - 熊喵君的博客 | PANDAYCHEN](https://pandaychen.github.io/2020/01/03/GRPC-RESOLVER-DEEP-ANALYSIS2-IN-KRATOS/)
