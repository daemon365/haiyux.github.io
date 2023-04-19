---
title: Framework Code
subtitle:
date: 2023-04-19T21:57:21+08:00
draft: false
toc: true
categories: 
  - cloud
tags: 
  - kubernetes
  - controller
authors:
    - haiyux
---

## Extender

### 作用

Extender可以通过添加额外的逻辑，使调度器具有更多的功能和更好的性能，从而更好地满足用户的需求。

### interface

- 用于外部进程影响 Kubernetes 的调度决策，通常用于 Kubernetes 直接未管理的资源

```GO
// Extender 是一个接口，用于外部进程影响 Kubernetes 进行调度的决策。这通常是针对 Kubernetes 未直接管理的资源。
type Extender interface {
	// Name 返回一个唯一的名称，用于标识 Extender
	Name() string

	// Filter 基于 Extender 实现的谓词函数进行筛选。筛选出的列表预期是所提供列表的子集。
    // failedNodes 和 failedAndUnresolvableNodes 可选包含失败的节点列表和失败原因，但后者中的节点是无法解决的。
    Filter(pod *v1.Pod, nodes []*v1.Node) (filteredNodes []*v1.Node, failedNodesMap extenderv1.FailedNodesMap, failedAndUnresolvable extenderv1.FailedNodesMap, err error)

	// Prioritize 基于 Extender 实现的优先级函数进行优先级排序。返回的分数和权重将用于计算 Extender 的加权得分。
    // 加权得分将添加到 Kubernetes 调度器计算的得分中。总得分将用于进行主机选择。
	Prioritize(pod *v1.Pod, nodes []*v1.Node) (hostPriorities *extenderv1.HostPriorityList, weight int64, err error)

	// Bind 将 Pod 绑定到节点。将绑定 Pod 到节点的操作委托给 Extender。
	Bind(binding *v1.Binding) error

	// IsBinder 返回此 Extender 是否配置为 Bind 方法。
	IsBinder() bool

	// IsInterested 如果此 Pod 请求的至少一个扩展资源由此 Extender 管理，则返回 true。
	IsInterested(pod *v1.Pod) bool

	// ProcessPreemption 函数返回通过 extender 处理后的具有其受影响 pod 的节点，具体根据如下给定信息进行处理：
    //  1. 要调度的 Pod
    //  2. 候选节点和受影响的 Pod（nodeNameToVictims），它们是之前调度过程中生成的
    // extender 可能做出的更改包括：
    //  1. 在 extender 的预抢占阶段之后，给定的候选节点的子集
    //  2. 在 extender 的预抢占阶段之后，每个给定的候选节点有不同的受影响 pod 集合
	ProcessPreemption(
		pod *v1.Pod,
		nodeNameToVictims map[string]*extenderv1.Victims,
		nodeInfos NodeInfoLister,
	) (map[string]*extenderv1.Victims, error)

	// SupportsPreemption 函数返回调度程序 extender 是否支持抢占。
	SupportsPreemption() bool

	// IsIgnorable 返回 true 表示当该 extender 不可用时，调度不应该失败。这使调度器能够快速失败并容忍非关键的 extender。
	IsIgnorable() bool
}
```

### HTTPExtender

```GO
// 定义一个名为 HTTPExtender 的结构体，用于存储 HTTPExtender 扩展程序的属性和方法
type HTTPExtender struct {
    // extenderURL 表示扩展程序的 URL 地址
    extenderURL string
    // preemptVerb 表示预处理操作的 HTTP 方法，如 GET、POST 等
    preemptVerb string
    // filterVerb 表示过滤操作的 HTTP 方法，如 GET、POST 等
    filterVerb string
    // prioritizeVerb 表示优先级操作的 HTTP 方法，如 GET、POST 等
    prioritizeVerb string
    // bindVerb 表示绑定操作的 HTTP 方法，如 GET、POST 等
    bindVerb string
    // weight 表示扩展程序的权重值，用于排序
    weight int64
    // client 表示 HTTP 客户端，用于发送 HTTP 请求
    client *http.Client
    // nodeCacheCapable 表示扩展程序是否支持节点缓存
    nodeCacheCapable bool
    // managedResources 表示扩展程序所管理的资源集合
    managedResources sets.Set[string]
    // ignorable 表示扩展程序是否可忽略
    ignorable bool
}
```

### New

```go
func NewHTTPExtender(config *schedulerapi.Extender) (framework.Extender, error) {
    // 判断HTTPTimeout是否设置，如果未设置则使用默认值
    if config.HTTPTimeout.Duration.Nanoseconds() == 0 {
        config.HTTPTimeout.Duration = time.Duration(DefaultExtenderTimeout)
    }

    // 创建http.RoundTripper对象
    transport, err := makeTransport(config)
    if err != nil {
        return nil, err
    }

    // 创建http.Client对象
    client := &http.Client{
        Transport: transport,
        Timeout:   config.HTTPTimeout.Duration,
    }

    // 创建一个空的字符串集合
    managedResources := sets.New[string]()
    // 遍历ManagedResources列表，并将其名称插入到集合中
    for _, r := range config.ManagedResources {
        managedResources.Insert(string(r.Name))
    }

    // 创建HTTPExtender对象，并返回
    return &HTTPExtender{
        extenderURL:      config.URLPrefix,
        preemptVerb:      config.PreemptVerb,
        filterVerb:       config.FilterVerb,
        prioritizeVerb:   config.PrioritizeVerb,
        bindVerb:         config.BindVerb,
        weight:           config.Weight,
        client:           client,
        nodeCacheCapable: config.NodeCacheCapable,
        managedResources: managedResources,
        ignorable:        config.Ignorable,
    }, nil
}

// 创建http.RoundTripper对象
func makeTransport(config *schedulerapi.Extender) (http.RoundTripper, error) {
    // 初始化restclient.Config对象
    var cfg restclient.Config
    // 如果存在TLS配置，则设置相应参数
    if config.TLSConfig != nil {
        cfg.TLSClientConfig.Insecure = config.TLSConfig.Insecure
        cfg.TLSClientConfig.ServerName = config.TLSConfig.ServerName
        cfg.TLSClientConfig.CertFile = config.TLSConfig.CertFile
        cfg.TLSClientConfig.KeyFile = config.TLSConfig.KeyFile
        cfg.TLSClientConfig.CAFile = config.TLSConfig.CAFile
        cfg.TLSClientConfig.CertData = config.TLSConfig.CertData
        cfg.TLSClientConfig.KeyData = config.TLSConfig.KeyData
        cfg.TLSClientConfig.CAData = config.TLSConfig.CAData
    }

    // 如果启用了HTTPS，则设置相应参数
    if config.EnableHTTPS {
        hasCA := len(cfg.CAFile) > 0 || len(cfg.CAData) > 0
        if !hasCA {
            cfg.Insecure = true
        }
    }

    // 根据配置创建TLS配置对象
    tlsConfig, err := restclient.TLSConfigFor(&cfg)
    if err != nil {
        return nil, err
    }

    // 根据TLS配置创建http.Transport对象，并返回http.RoundTripper对象
    if tlsConfig != nil {
        return utilnet.SetTransportDefaults(&http.Transport{
            TLSClientConfig: tlsConfig,
        }), nil
    }
    return utilnet.SetTransportDefaults(&http.Transport{}), nil
}
```

### 方法

```GO
func (h *HTTPExtender) Name() string {
	return h.extenderURL
}

// 该函数实现了基于扩展程序实现的过滤函数，它期望过滤后的节点列表是提供的节点列表的子集，否则将返回一个错误。
// 失败的节点和失败的不可解决节点可选地包含了失败节点的列表和失败原因，但不包括后者是不可解决的节点。
func (h *HTTPExtender) Filter(
    pod *v1.Pod,
    nodes []*v1.Node,
    ) (filteredList []*v1.Node, failedNodes, failedAndUnresolvableNodes extenderv1.FailedNodesMap, err error) {
    var (
        result extenderv1.ExtenderFilterResult
        nodeList *v1.NodeList
        nodeNames *[]string
        nodeResult []*v1.Node
        args *extenderv1.ExtenderArgs
    )
    // 使用字典存储提供的节点列表
    fromNodeName := make(map[string]*v1.Node)
    for _, n := range nodes {
    	fromNodeName[n.Name] = n
	}
    // 如果 filterVerb 为空，则返回全部节点列表
    if h.filterVerb == "" {
        return nodes, extenderv1.FailedNodesMap{}, extenderv1.FailedNodesMap{}, nil
    }

    // 如果扩展程序支持节点缓存，则将节点名放入 nodeNameSlice 列表中
    if h.nodeCacheCapable {
        nodeNameSlice := make([]string, 0, len(nodes))
        for _, node := range nodes {
            nodeNameSlice = append(nodeNameSlice, node.Name)
        }
        nodeNames = &nodeNameSlice
    } else {
        // 如果扩展程序不支持节点缓存，则将节点列表放入 nodeList 中
        nodeList = &v1.NodeList{}
        for _, node := range nodes {
            nodeList.Items = append(nodeList.Items, *node)
        }
    }

    args = &extenderv1.ExtenderArgs{
        Pod:       pod,
        Nodes:     nodeList,
        NodeNames: nodeNames,
    }

    // 向扩展程序发送请求并获取结果
    if err := h.send(h.filterVerb, args, &result); err != nil {
        return nil, nil, nil, err
    }
    if result.Error != "" {
        return nil, nil, nil, fmt.Errorf(result.Error)
    }

    // 如果扩展程序支持节点缓存且返回了节点名，则将节点列表转换为 nodeResult 列表
    if h.nodeCacheCapable && result.NodeNames != nil {
        nodeResult = make([]*v1.Node, len(*result.NodeNames))
        for i, nodeName := range *result.NodeNames {
            if n, ok := fromNodeName[nodeName]; ok {
                nodeResult[i] = n
            } else {
                return nil, nil, nil, fmt.Errorf(
                    "extender %q claims a filtered node %q which is not found in the input node list",
                    h.extenderURL, nodeName)
            }
        }
    } else if result.Nodes != nil {
        // 如果扩展程序不支持节点缓存且返回了节点列表，则将返回的节点列表转换为 nodeResult 列表
        nodeResult = make([]*v1.Node, len(result.Nodes.Items))
        for i := range result.Nodes.Items {
            nodeResult[i] = &result.Nodes.Items[i]
        }
    }

    return nodeResult, result.FailedNodes, result
}

func (h *HTTPExtender) Prioritize(pod *v1.Pod, nodes []*v1.Node) (*extenderv1.HostPriorityList, int64, error) {
	var (
		result    extenderv1.HostPriorityList // 定义一个类型为extenderv1.HostPriorityList的变量result，用于存放结果
		nodeList  *v1.NodeList // 定义一个类型为v1.NodeList指针的变量nodeList，用于存放Node列表
		nodeNames *[]string // 定义一个类型为字符串切片指针的变量nodeNames，用于存放Node的名称列表
		args      *extenderv1.ExtenderArgs // 定义一个类型为extenderv1.ExtenderArgs指针的变量args，用于存放调度器参数
	)

	if h.prioritizeVerb == "" { // 如果h.prioritizeVerb为空字符串
		result := extenderv1.HostPriorityList{} // 创建一个空的extenderv1.HostPriorityList类型的变量result
		for _, node := range nodes { // 遍历nodes中的每个Node
			result = append(result, extenderv1.HostPriority{Host: node.Name, Score: 0}) // 将Node的名称和分数0添加到result中
		}
		return &result, 0, nil // 返回result指针、0分数和nil错误
	}

	if h.nodeCacheCapable { // 如果h.nodeCacheCapable为真
		nodeNameSlice := make([]string, 0, len(nodes)) // 创建一个长度为0、容量为len(nodes)的字符串切片nodeNameSlice
		for _, node := range nodes { // 遍历nodes中的每个Node
			nodeNameSlice = append(nodeNameSlice, node.Name) // 将Node的名称添加到nodeNameSlice中
		}
		nodeNames = &nodeNameSlice // 将nodeNameSlice的指针赋值给nodeNames
	} else {
		nodeList = &v1.NodeList{} // 创建一个空的v1.NodeList类型的变量nodeList
		for _, node := range nodes { // 遍历nodes中的每个Node
			nodeList.Items = append(nodeList.Items, *node) // 将Node的值添加到nodeList的Items字段中
		}
	}

	args = &extenderv1.ExtenderArgs{ // 创建一个extenderv1.ExtenderArgs类型的变量args，并初始化其字段
		Pod:       pod, // 将pod参数赋值给args的Pod字段
		Nodes:     nodeList, // 将nodeList赋值给args的Nodes字段
		NodeNames: nodeNames, // 将nodeNames赋值给args的NodeNames字段
	}

	if err := h.send(h.prioritizeVerb, args, &result); err != nil { // 调用h.send方法发送请求，将h.prioritizeVerb、args和result作为参数传递，并检查返回的错误
		return nil, 0, err // 如果有错误，返回nil指针、0分数和错误
	}
	return &result, h.weight, nil // 返回result指针、h.weight字段的值和nil错误
}

// Bind 将绑定 Pod 到节点的操作委托给 Extender。
func (h *HTTPExtender) Bind(binding *v1.Binding) error {
    var result extenderv1.ExtenderBindingResult // 用于保存绑定结果的变量
    if !h.IsBinder() { // 检查当前 Extender 是否为 Binder，如果不是则返回错误
        // 这不应该发生，因为这个 Extender 不应该成为 Binder。
        return fmt.Errorf("unexpected empty bindVerb in extender")
    }
    req := &extenderv1.ExtenderBindingArgs{ // 创建用于绑定的参数对象
        PodName: binding.Name, // 设置 Pod 的名称
        PodNamespace: binding.Namespace, // 设置 Pod 的命名空间
        PodUID: binding.UID, // 设置 Pod 的 UID
        Node: binding.Target.Name, // 设置目标节点的名称
    }
    if err := h.send(h.bindVerb, req, &result); err != nil { // 调用 send 方法发送绑定请求，并将结果保存到 result 变量中
    	return err // 如果出现错误，返回错误信息
    }
    if result.Error != "" { // 检查绑定结果中是否包含错误信息，如果有，则返回错误
    	return fmt.Errorf(result.Error)
    }
    return nil // 如果没有错误，返回 nil
}

func (h *HTTPExtender) IsBinder() bool {
	return h.bindVerb != ""
}

func (h *HTTPExtender) IsInterested(pod *v1.Pod) bool {
    if h.managedResources.Len() == 0 { // 检查 Extender 是否管理的资源列表为空，如果为空，则返回 true
    	return true
    }
    if h.hasManagedResources(pod.Spec.Containers) { // 检查 Pod 中的容器是否包含 Extender 管理的资源，如果包含，则返回 true
    	return true
    }
    if h.hasManagedResources(pod.Spec.InitContainers) { // 检查 Pod 中的 Init 容器是否包含 Extender 管理的资源，如果包含，则返回 true
    	return true
    }
    return false // 如果都不满足以上条件，则返回 false
}

func (h *HTTPExtender) ProcessPreemption(
	pod *v1.Pod,                          // 输入参数1: Pod 对象
	nodeNameToVictims map[string]*extenderv1.Victims,  // 输入参数2: 节点名到受影响 Pod 列表的映射
	nodeInfos framework.NodeInfoLister,    // 输入参数3: 节点信息的列表
) (map[string]*extenderv1.Victims, error) {    // 返回值: 节点名到受影响 Pod 列表的映射和错误信息

	var (
		result extenderv1.ExtenderPreemptionResult
		args   *extenderv1.ExtenderPreemptionArgs
	)

	if !h.SupportsPreemption() {    // 判断当前 extender 是否支持抢占操作
		return nil, fmt.Errorf("preempt verb is not defined for extender %v but run into ProcessPreemption", h.extenderURL)
	}

	if h.nodeCacheCapable {    // 判断当前 extender 是否支持节点缓存
		// 如果 extender 支持节点缓存，将 nodeNameToVictims 转换为 nodeNameToMetaVictims，并传入参数 args
		nodeNameToMetaVictims := convertToMetaVictims(nodeNameToVictims)
		args = &extenderv1.ExtenderPreemptionArgs{
			Pod:                   pod,
			NodeNameToMetaVictims: nodeNameToMetaVictims,
		}
	} else {
		// 如果 extender 不支持节点缓存，直接将 nodeNameToVictims 传入参数 args
		args = &extenderv1.ExtenderPreemptionArgs{
			Pod:               pod,
			NodeNameToVictims: nodeNameToVictims,
		}
	}

	if err := h.send(h.preemptVerb, args, &result); err != nil {    // 调用 extender 的 send 方法发送请求并获取响应结果
		return nil, err
	}

	// Extender 总是返回 NodeNameToMetaVictims，因此使用 nodeInfos 将其转换为 NodeNameToVictims。
	newNodeNameToVictims, err := h.convertToVictims(result.NodeNameToMetaVictims, nodeInfos)
	if err != nil {
		return nil, err
	}
	// 不覆盖 nodeNameToVictims。
	return newNodeNameToVictims, nil    // 返回经过转换后的节点名到受影响 Pod 列表的映射和错误信息
}

// SupportsPreemption 如果 extender 支持抢占操作，则返回 true。
// 一个 extender 应该定义 preempt 动词并启用自己的节点缓存。
func (h *HTTPExtender) SupportsPreemption() bool {
	return len(h.preemptVerb) > 0
}

// IsIgnorable 当此 extender 不可用时，返回 true，表示调度不应失败。
func (h *HTTPExtender) IsIgnorable() bool {
	return h.ignorable
}
```

#### send

```go
// send 是一个辅助函数，用于向 extender 发送消息。
func (h *HTTPExtender) send(action string, args interface{}, result interface{}) error {
    out, err := json.Marshal(args)
    if err != nil {
    	return err
    }
	url := strings.TrimRight(h.extenderURL, "/") + "/" + action

    req, err := http.NewRequest("POST", url, bytes.NewReader(out))
    if err != nil {
        return err
    }

    req.Header.Set("Content-Type", "application/json")

    resp, err := h.client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("failed %v with extender at URL %v, code %v", action, url, resp.StatusCode)
    }

    return json.NewDecoder(resp.Body).Decode(result)
}
```

#### hasManagedResources

```go
func (h *HTTPExtender) hasManagedResources(containers []v1.Container) bool {
// 判断容器中是否有受管理的资源
    for i := range containers {
        container := &containers[i]
        for resourceName := range container.Resources.Requests {
            if h.managedResources.Has(string(resourceName)) {
            	return true
        	}
        }
        for resourceName := range container.Resources.Limits {
            if h.managedResources.Has(string(resourceName)) {
            	return true
            }
        }
    }
    return false
}
```

#### convertToMetaVictims

```go
func convertToMetaVictims(
		nodeNameToVictims map[string]*extenderv1.Victims,
	) map[string]*extenderv1.MetaVictims {
    // 将节点名称到受害者对象的映射转换为节点名称到元受害者对象的映射
    nodeNameToMetaVictims := map[string]*extenderv1.MetaVictims{}
    for node, victims := range nodeNameToVictims {
        metaVictims := &extenderv1.MetaVictims{
            Pods: []*extenderv1.MetaPod{},
            NumPDBViolations: victims.NumPDBViolations,
        }
        for _, pod := range victims.Pods {
            metaPod := &extenderv1.MetaPod{
            	UID: string(pod.UID),
            }
        	metaVictims.Pods = append(metaVictims.Pods, metaPod)
        }
        nodeNameToMetaVictims[node] = metaVictims
    }
    return nodeNameToMetaVictims
}
```

#### convertPodUIDToPod

```go
func (h *HTTPExtender) convertPodUIDToPod(
    metaPod *extenderv1.MetaPod,
    nodeInfo *framework.NodeInfo) (*v1.Pod, error) {
    // 将元Pod对象转换为实际Pod对象
    for _, p := range nodeInfo.Pods {
        if string(p.Pod.UID) == metaPod.UID {
        	return p.Pod, nil
        }
    }
    return nil, fmt.Errorf("extender: %v claims to preempt pod (UID: %v) on node: %v, but the pod is not found on that node",
    h.extenderURL, metaPod, nodeInfo.Node().Name)
}
```

#### convertToVictims

```go
func (h *HTTPExtender) convertToVictims(
    nodeNameToMetaVictims map[string]*extenderv1.MetaVictims,
    nodeInfos framework.NodeInfoLister,
    ) (map[string]*extenderv1.Victims, error) {
    // 将节点名称到元受害者对象的映射转换为节点名称到受害者对象的映射
    nodeNameToVictims := map[string]*extenderv1.Victims{}
    for nodeName, metaVictims := range nodeNameToMetaVictims {
    	nodeInfo, err := nodeInfos.Get(nodeName)
        if err != nil {
        	return nil, err
        }
        victims := &extenderv1.Victims{
            Pods: []*v1.Pod{},
            NumPDBViolations: metaVictims.NumPDBViolations,
    	}
        for _, metaPod := range metaVictims.Pods {
            pod, err := h.convertPodUIDToPod(metaPod, nodeInfo)
            if err != nil {
            	return nil, err
            }
    		victims.Pods = append(victims.Pods, pod)
    	}
    	nodeNameToVictims[nodeName] = victims
    }
    return nodeNameToVictims, nil
}
```

## Framework

### 作用

Framework接口定义了Kubernetes调度框架的行为规范，它是Kubernetes调度器的核心接口。Kubernetes调度器将调度决策委托给一组调度器插件（scheduler plugins），这些插件实现了Framework接口中定义的方法。

通过实现Framework接口中的方法，调度器插件可以检查、过滤和打分各个节点上的Pod，然后选择最佳的节点将Pod绑定到该节点上运行。此外，Framework接口还定义了一些其他方法，例如获取已配置的插件列表、设置PodNominator等。

总之，Framework接口提供了Kubernetes调度器的基本行为规范和扩展点，使得Kubernetes调度器可以方便地与各种自定义插件集成，从而实现高效、灵活的资源调度。

### interface

```GO
// Framework 是一个接口，管理调度框架中使用的插件集。
// 配置好的插件会在调度上下文中指定的点被调用。
type Framework interface {
	Handle
    // PreEnqueuePlugins 返回已注册的 preEnqueue 插件。
    PreEnqueuePlugins() []PreEnqueuePlugin

    // QueueSortFunc 返回排序调度队列中 Pod 的函数。
    QueueSortFunc() LessFunc

    // RunPreFilterPlugins 运行已配置的 PreFilter 插件集。如果任何插件返回的状态不是 Success，则返回 *Status，状态代码设置为非成功状态。
    // 如果返回一个非成功的状态，则调度循环将被中止。
    // 它还返回一个 PreFilterResult，它可能会影响向下评估哪些或多少个节点。
    RunPreFilterPlugins(ctx context.Context, state *CycleState, pod *v1.Pod) (*PreFilterResult, *Status)

    // RunPostFilterPlugins 运行已配置的 PostFilter 插件集。
    // PostFilter 插件可以是信息性的，如果是，则应配置为首先执行并返回 Unschedulable 状态；
    // 或者它们可以尝试更改集群状态，使 Pod 可以在将来的调度周期中调度。
    RunPostFilterPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, filteredNodeStatusMap NodeToStatusMap) (*PostFilterResult, *Status)

    // RunPreBindPlugins 运行已配置的 PreBind 插件集。如果任何插件返回的状态不是 Success，则返回 *Status，状态代码设置为非成功状态。
    // 如果状态代码是 "Unschedulable"，则认为它是调度检查失败，否则认为是内部错误。在任何情况下，Pod 都不会绑定。
    RunPreBindPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string) *Status

    // RunPostBindPlugins 运行已配置的 PostBind 插件集。
    RunPostBindPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string)

    // RunReservePluginsReserve 运行配置的 Reserve 插件集的 Reserve 方法。如果其中任何一个调用返回错误，则不会继续运行其余插件并返回错误。
    // 在这种情况下，Pod 将不会被调度。
    RunReservePluginsReserve(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string) *Status

    // RunReservePluginsUnreserve 运行已配置的 Reserve 插件集的 Unreserve 方法。
    RunReservePluginsUnreserve(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string)

  	// RunPermitPlugins 运行配置的 Permit 插件集合。如果任何一个插件返回的状态不是 "Success" 或 "Wait"，它将不会继续运行其余的插件，并返回一个错误。
    // 否则，如果任何一个插件返回 "Wait"，则此函数将创建并添加一个等待 Pod 到当前等待 Pod 映射中，并返回带有 "Wait" 状态的结果。Pod 将保持等待状态的最小持续时间由 Permit 插件返回。
	RunPermitPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string) *Status

	// WaitOnPermit 如果 Pod 是等待 Pod，则会阻塞，直到等待 Pod 被拒绝或允许。
	WaitOnPermit(ctx context.Context, pod *v1.Pod) *Status

	// RunBindPlugins 运行配置的 Bind 插件集合。Bind 插件可以选择是否处理给定的 Pod。如果 Bind 插件选择跳过绑定，则应返回 code=5（"skip"）状态。
    // 否则，它应返回 "Error" 或 "Success"。如果没有插件处理绑定，则 RunBindPlugins 返回 code=5（"skip"）状态。
	RunBindPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string) *Status

	// HasFilterPlugins 如果至少有一个 Filter 插件被定义，则返回 true。
	HasFilterPlugins() bool

	// HasPostFilterPlugins 如果至少有一个 PostFilter 插件被定义，则返回 true。
	HasPostFilterPlugins() bool

	// HasScorePlugins 如果至少有一个 Score 插件被定义，则返回 true。
	HasScorePlugins() bool

	// ListPlugins 返回扩展点名称到配置的插件列表的映射。
	ListPlugins() *config.Plugins

	// ProfileName 返回与配置文件相关联的配置文件名称。
	ProfileName() string

	// PercentageOfNodesToScore 返回与配置文件相关联的 percentageOfNodesToScore。
	PercentageOfNodesToScore() *int32

	// SetPodNominator 设置 PodNominator。
	SetPodNominator(nominator PodNominator)
}
```

#### Plugin

```GO
type Plugin interface {
	Name() string
}
```

#### Status

```go
// Status 表示运行插件的结果。它由一个 code，一条消息，（可选的）一个错误，以及导致失败的插件名称组成。
// 当状态码不是 Success 时，原因应该解释为什么失败。
// 当 code 是 Success 时，所有其他字段应该为空。
// 注意：nil 状态也被认为是 Success。
type Status struct {
    code Code // 描述状态码的枚举类型
    reasons []string // 保存状态码不是 Success 时的错误原因，可能有多个
    err error // 保存任何可能出现的错误
    // failedPlugin 是一个可选的字段，记录 Pod 失败的插件名称。
    // 当 code 是 Error、Unschedulable 或 UnschedulableAndUnresolvable 时，由框架设置。
    failedPlugin string
}

type Code int

// 这些是在状态中使用的预定义代码。
const (
    // Success 表示插件正确运行并找到了可被调度的 Pod。
    // 注意：一个 nil 状态也被视为“Success”。
    Success Code = iota
    // Error 用于表示内部插件错误、意外输入等情况。
    Error
    // Unschedulable 表示插件发现一个无法调度的 Pod。调度器可能会尝试运行其他 postFilter 插件，如抢占，以便将此 Pod 调度。
    // 使用 UnschedulableAndUnresolvable 来使调度器跳过其他 postFilter 插件。
    // 附带的状态消息应解释为什么该 Pod 无法调度。
    Unschedulable
    // UnschedulableAndUnresolvable 表示插件发现一个无法调度的 Pod，并且其他 postFilter 插件（如抢占）也无法改变这种情况。
    // 如果在运行其他 postFilter 插件后可能可以调度该 Pod，则插件应返回 Unschedulable。
    // 附带的状态消息应解释为什么该 Pod 无法调度。
    UnschedulableAndUnresolvable
    // Wait 表示 Permit 插件发现应等待调度 Pod。
    Wait
    // Skip 在以下情况下使用：
    // - 当 Bind 插件选择跳过绑定时。
    // - 当 PreFilter 插件返回 Skip 以跳过耦合的 Filter 插件/PreFilterExtensions()。
    // - 当 PreScore 插件返回 Skip 以跳过耦合的 Score 插件。
    Skip
)

var codes = []string{"Success", "Error", "Unschedulable", "UnschedulableAndUnresolvable", "Wait", "Skip"}

func (c Code) String() string {
	return codes[c]
}
```

#### PreEnqueuePlugin

```GO
// PreEnqueuePlugin是一个接口，必须由“PreEnqueue”插件实现。
// 这些插件在将Pod添加到activeQ之前被调用。
// 注意：预先插入插件应该是轻量级和高效的，因此不应该涉及访问外部端点等昂贵的调用；
// 否则它将阻塞事件处理程序中其他Pod的排队。
type PreEnqueuePlugin interface {
    Plugin
    // PreEnqueue在将Pod添加到activeQ之前被调用。
    PreEnqueue(ctx context.Context, p *v1.Pod) *Status
}
```

#### LessFunc

```GO
// LessFunc 是对pod信息进行排序的功能
type LessFunc func(podInfo1, podInfo2 *QueuedPodInfo) bool
```

#### PreFilterResult

```GO
// PreFilterResult 包装了调度框架在 PreFilter 阶段需要使用的一些信息。
type PreFilterResult struct {
    // 应考虑的节点集；如果为 nil，则所有节点均符合条件。
    NodeNames sets.Set[string]
}
```

#### NodeToStatusMap

```GO
type NodeToStatusMap map[string]*Status
```

#### PostFilterResult

```GO
// 定义 PostFilterResult 类型
type PostFilterResult struct {
	*NominatingInfo // 一个指向 NominatingInfo 结构体的指针
}
```

##### NominatingInfo

```GO
type NominatingInfo struct {
    NominatedNodeName string // 被提名的节点的名称
    NominatingMode NominatingMode // 提名模式
}
```

##### NominatingMode

```GO
type NominatingMode int

const (
    // 表示进行候选人提名，也就是不对集群状态进行任何修改，而是直接返回当前集群状态
	ModeNoop NominatingMode = iota
    // 表示进行候选人提名并更新集群状态，也就是会修改集群状态，以便后续操作可以基于新的集群状态进行
	ModeOverride
)
```

#### CycleState

```go
// CycleState 提供了一种机制，使得插件可以存储和检索任意数据。
// 由一个插件存储的 StateData 可以被另一个插件读取、修改或删除。
// CycleState 不提供任何数据保护，因为所有的插件都被认为是可信的。
// 注意：CycleState 使用 sync.Map 来支持存储。它旨在优化“写一次，读多次”的场景。
// 它是所有内部插件中推荐使用的模式——插件特定的状态在 PreFilter/PreScore 中写入一次，然后在 Filter/Score 中读取多次。
type CycleState struct {
	// 存储使用 StateKey 作为键，StateData 作为值。
    storage sync.Map
    // 如果 recordPluginMetrics 为 true，则为此周期记录 PluginExecutionDuration。
    recordPluginMetrics bool
    // SkipFilterPlugins 是在 Filter 扩展点中将被跳过的插件集合。
    SkipFilterPlugins sets.Set[string]
    // SkipScorePlugins 是在 Score 扩展点中将被跳过的插件集合。
	SkipScorePlugins sets.Set[string]
}

type StateKey string

func NewCycleState() *CycleState {
	return &CycleState{}
}
```

##### 方法

```GO
// ShouldRecordPluginMetrics 返回是否应该记录 PluginExecutionDuration 指标。
func (c *CycleState) ShouldRecordPluginMetrics() bool {
    if c == nil {
    	return false
    }
    return c.recordPluginMetrics
}

// SetRecordPluginMetrics 将 recordPluginMetrics 设置为给定值。
func (c *CycleState) SetRecordPluginMetrics(flag bool) {
    if c == nil {
    	return
    }
    c.recordPluginMetrics = flag
}

// Clone 创建 CycleState 的副本并返回其指针。如果要克隆的上下文为 nil，则 Clone 返回 nil。
func (c *CycleState) Clone() *CycleState {
    if c == nil {
    	return nil
    }
    copy := NewCycleState()
    c.storage.Range(func(k, v interface{}) bool {
        copy.storage.Store(k, v.(StateData).Clone())
        return true
    })
    copy.recordPluginMetrics = c.recordPluginMetrics
    copy.SkipFilterPlugins = c.SkipFilterPlugins
    copy.SkipScorePlugins = c.SkipScorePlugins
    return copy
}

// Read 从 CycleState 中检索具有给定“key”的数据。如果该键不存在，则返回错误。
// 此函数通过使用 sync.Map 实现线程安全。
func (c *CycleState) Read(key StateKey) (StateData, error) {
    if v, ok := c.storage.Load(key); ok {
    	return v.(StateData), nil
    }
    return nil, ErrNotFound
}

// Write 将给定的“val”存储在 CycleState 中，并使用给定的“key”。
// 此函数通过使用 sync.Map 实现线程安全。
func (c *CycleState) Write(key StateKey, val StateData) {
	c.storage.Store(key, val)
}

// Delete 从 CycleState 中删除具有给定键的数据。
// 此函数通过使用 sync.Map 实现线程安全。
func (c *CycleState) Delete(key StateKey) {
	c.storage.Delete(key)
}
```

### Handle

```go
// Handle 提供数据和一些工具，供插件使用。它在插件初始化时传递给插件工厂。插件必须存储并使用此句柄来调用框架函数。
type Handle interface {
    // PodNominator 抽象了维护被提名的Pod的操作。
    PodNominator
    // PluginsRunner 抽象了运行某些插件的操作。
    PluginsRunner
    // SnapshotSharedLister 返回最新的NodeInfo快照中的Listers。该快照在调度周期开始时进行，直到Pod完成“许可”点之前保持不变。
    // 在调度绑定阶段期间，无法保证信息保持不变，因此绑定周期（pre-bind/bind/post-bind/un-reserve插件）中的插件不应使用它，否则可能会发生并发读/写错误，它们应该使用调度器缓存。
    SnapshotSharedLister() SharedLister
    // IterateOverWaitingPods 获取读锁并遍历WaitingPods映射。
    IterateOverWaitingPods(callback func(WaitingPod))

    // GetWaitingPod 根据UID返回等待的Pod。
    GetWaitingPod(uid types.UID) WaitingPod

    // RejectWaitingPod 拒绝给定UID的等待Pod。返回值指示Pod是否在等待中。
    RejectWaitingPod(uid types.UID) bool

    // ClientSet 返回一个Kubernetes ClientSet。
    ClientSet() clientset.Interface

    // KubeConfig 返回原始kube config。
    KubeConfig() *restclient.Config

    // EventRecorder 返回事件记录器。
    EventRecorder() events.EventRecorder

    SharedInformerFactory() informers.SharedInformerFactory

    // RunFilterPluginsWithNominatedPods 在给定节点上运行配置的过滤插件集以过滤被提名的Pod。
    RunFilterPluginsWithNominatedPods(ctx context.Context, state *CycleState, pod *v1.Pod, info *NodeInfo) *Status

    // Extenders 返回已注册的调度器扩展程序。
    Extenders() []Extender

    // Parallelizer 返回一个持有调度程序并行性的Parallelizer。
    Parallelizer() parallelize.Parallelizer
}
```

#### PodNominator

```go
type PodNominator interface {
	// AddNominatedPod将给定的Pod添加到提名器中，如果该Pod已经存在，则进行更新。
	AddNominatedPod(pod *PodInfo, nominatingInfo *NominatingInfo)
	// DeleteNominatedPodIfExists从内部缓存中删除提名的Pod。如果该Pod不存在，则此操作不会执行任何操作。
	DeleteNominatedPodIfExists(pod *v1.Pod)
	// UpdateNominatedPod使用newPodInfo更新oldPod。
	UpdateNominatedPod(oldPod *v1.Pod, newPodInfo *PodInfo)
	// NominatedPodsForNode返回给定节点上的提名Pod。
	NominatedPodsForNode(nodeName string) []*PodInfo
}
```

##### PluginsRunner

```go
// PluginsRunner接口抽象了运行一些插件的操作。
// 当进行某些运行中的pod被驱逐时，预选阶段后置过滤器插件用于评估在哪些节点上可以调度pod时会使用这个接口。
type PluginsRunner interface {
    // RunPreScorePlugins运行一组配置好的PreScore插件。如果这些插件中的任何一个返回除"Success"以外的任何状态，则拒绝给定的pod。
    RunPreScorePlugins(context.Context, *CycleState, *v1.Pod, []*v1.Node) Status
    // RunScorePlugins运行一组配置好的得分插件。
    // 它返回一个列表，该列表存储来自每个插件的分数以及每个Node的总分数。
    // 它还返回Status，如果任何插件返回非"Success"状态，则将其设置为非"Success"状态。
    RunScorePlugins(context.Context, *CycleState, *v1.Pod, []*v1.Node) ([]NodePluginScores, *Status)
    // RunFilterPlugins在给定节点上运行为pod配置的一组过滤插件。
    // 请注意，对于正在评估的节点，传递的nodeInfo引用可能与NodeInfoSnapshot映射中的引用不同（例如，被认为在该节点上运行的pod可能不同）。
    // 例如，在预期抢占期间，我们可能会传递原始nodeInfo对象的副本，该副本已从其中删除了一些pod，以评估抢占它们以调度目标pod的可能性。
    RunFilterPlugins(context.Context, *CycleState, *v1.Pod, *NodeInfo) *Status
    // RunPreFilterExtensionAddPod调用配置好的一组PreFilter插件的AddPod接口。
    // 如果这些插件中的任何一个返回除Success以外的任何状态，则直接返回。
    RunPreFilterExtensionAddPod(ctx context.Context, state *CycleState, podToSchedule *v1.Pod, podInfoToAdd *PodInfo, nodeInfo *NodeInfo) *Status
    // RunPreFilterExtensionRemovePod调用配置好的一组PreFilter插件的RemovePod接口。
    // 如果这些插件中的任何一个返回除Success以外的任何状态，则直接返回。
    RunPreFilterExtensionRemovePod(ctx context.Context, state *CycleState, podToSchedule *v1.Pod, podInfoToRemove *PodInfo, nodeInfo *NodeInfo) *Status
}
```

###### NodePluginScores

```go
// NodePluginScores是一个结构体，包含节点名称以及该节点的分数。
type NodePluginScores struct {
    // Name是节点名称。
    Name string
    // Scores是来自插件和扩展程序的分数。
    Scores []PluginScore
    // TotalScore是Scores中的总分数。
    TotalScore int64
}

// PluginScore是一个结构体，包含插件或扩展程序的名称和分数。
type PluginScore struct {
    // Name是插件或扩展程序的名称。
    Name string
    Score int64
}
```

#### SharedLister

```go
type SharedLister interface {
	NodeInfos() NodeInfoLister
	StorageInfos() StorageInfoLister
}

// NodeInfoLister 接口表示能够通过节点名称列表/获取 NodeInfo 对象的任何内容。
type NodeInfoLister interface {
    // List 返回 NodeInfos 的列表。
    List() ([]*NodeInfo, error)
    // HavePodsWithAffinityList 返回具有亲和性项的 Pod 的 NodeInfos 列表。
    HavePodsWithAffinityList() ([]*NodeInfo, error)
    // HavePodsWithRequiredAntiAffinityList 返回具有必需反亲和性项的 Pod 的 NodeInfos 列表。
    HavePodsWithRequiredAntiAffinityList() ([]*NodeInfo, error)
    // Get 返回给定节点名称的 NodeInfo。
    Get(nodeName string) (*NodeInfo, error)
}

// StorageInfoLister 接口表示处理存储相关操作和资源的任何内容。
type StorageInfoLister interface {
    // IsPVCUsedByPods 根据格式为 "namespace/name" 的键返回 PVC 是否被一个或多个已调度的 Pod 使用的 true/false 值。
    IsPVCUsedByPods(key string) bool
}
```

#### WaitingPod

```go
// WaitingPod表示当前处于许可阶段等待的Pod。
type WaitingPod interface {
    // GetPod返回对等待Pod的引用。
    GetPod() *v1.Pod
    // GetPendingPlugins返回挂起的Permit插件名称列表。
    GetPendingPlugins() []string
    // Allow声明允许由名为“pluginName”的插件调度等待的Pod。
    // 如果这是最后一个允许的插件，则会发送成功信号以解除Pod的阻塞。
    Allow(pluginName string)
    // Reject声明等待的Pod无法调度。
    Reject(pluginName，msg string)
}
```

