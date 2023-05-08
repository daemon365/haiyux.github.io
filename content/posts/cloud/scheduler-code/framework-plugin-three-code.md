---
title: "kubernetes scheduler默认的插件代码走读(3)"
subtitle:
date: 2023-05-08T21:12:05+08:00
draft: false
toc: true
categories: 
  - cloud
tags: 
  - kubernetes
  - controller
authors:
    - haiyux
featuredImagePreview: /img/preview/scheduler/scheduler-plugin-3.jpg
---

## PodTopologySpread

### 作用

在集群中的不同拓扑域（Topology Domain）之间平衡Pod的分布。

在Kubernetes集群中，节点可以被分组到拓扑域中，例如机架、区域或数据中心。这些拓扑域可能会有不同的硬件限制或故障域，因此在不同的拓扑域之间平衡Pod的分布可以提高集群的可靠性和稳定性。

PodTopologySpread插件可以通过在不同的拓扑域之间分散Pod的调度来实现这一目标。具体来说，它可以通过以下两种方式来平衡Pod的分布：

1. 在不同的拓扑域中选择合适的节点。例如，在一个由三个机架组成的集群中，PodTopologySpread可以确保Pod被分配到每个机架中的节点，而不是只集中在某一个机架中。
2. 在同一拓扑域中选择合适的节点。例如，在一个由三个区域组成的集群中，PodTopologySpread可以确保Pod被分配到每个区域中的节点，而不是只集中在某一个区域中。

通过使用PodTopologySpread插件，管理员可以有效地平衡Pod的分布，从而提高集群的可靠性和稳定性。

### 结构

```GO
// PodTopologySpread is a plugin that ensures pod's topologySpreadConstraints is satisfied.
type PodTopologySpread struct {
    // 标识该插件是否被系统默认启用
    systemDefaulted bool
    // 并行执行器
    parallelizer parallelize.Parallelizer
    // 默认的 TopologySpreadConstraint 列表
    defaultConstraints []v1.TopologySpreadConstraint
    // 共享列表
    sharedLister framework.SharedLister
    // Service 列表
    services corelisters.ServiceLister
    // ReplicationController 列表
    replicationCtrls corelisters.ReplicationControllerLister
    // ReplicaSet 列表
    replicaSets appslisters.ReplicaSetLister
    // StatefulSet 列表
    statefulSets appslisters.StatefulSetLister
    // 是否启用 PodTopologySpread 中的 MinDomains
    enableMinDomainsInPodTopologySpread bool
    // 是否启用 PodTopologySpread 中的 NodeInclusionPolicy
    enableNodeInclusionPolicyInPodTopologySpread bool
    // 是否启用 PodTopologySpread 中的 MatchLabelKeys
    enableMatchLabelKeysInPodTopologySpread bool
}

// 实现了 framework.PreFilterPlugin 接口
var _ framework.PreFilterPlugin = &PodTopologySpread{}
// 实现了 framework.FilterPlugin 接口
var _ framework.FilterPlugin = &PodTopologySpread{}
// 实现了 framework.PreScorePlugin 接口
var _ framework.PreScorePlugin = &PodTopologySpread{}
// 实现了 framework.ScorePlugin 接口
var _ framework.ScorePlugin = &PodTopologySpread{}
// 实现了 framework.EnqueueExtensions 接口
var _ framework.EnqueueExtensions = &PodTopologySpread{}

// Name 是插件在插件注册表和配置中使用的名称
const Name = names.PodTopologySpread

// 实现了 framework.Plugin 接口中的 Name() 方法，返回插件的名称
func (pl *PodTopologySpread) Name() string {
    return Name
}

// New initializes a new plugin and returns it.
func New(plArgs runtime.Object, h framework.Handle, fts feature.Features) (framework.Plugin, error) {
    // 检查是否存在 SnapshotSharedLister
    if h.SnapshotSharedLister() == nil {
        return nil, fmt.Errorf("SnapshotSharedlister is nil")
    }
    // 从参数中获取 PodTopologySpreadArgs 对象
    args, err := getArgs(plArgs)
    if err != nil {
        return nil, err
    }
    // 校验 PodTopologySpread 参数是否合法
    if err := validation.ValidatePodTopologySpreadArgs(nil, &args); err != nil {
        return nil, err
    }
    // 创建 PodTopologySpread 对象
    pl := &PodTopologySpread{
        parallelizer: h.Parallelizer(),
        sharedLister: h.SnapshotSharedLister(),
        defaultConstraints: args.DefaultConstraints,
        enableMinDomainsInPodTopologySpread: fts.EnableMinDomainsInPodTopologySpread,
        enableNodeInclusionPolicyInPodTopologySpread: fts.EnableNodeInclusionPolicyInPodTopologySpread,
        enableMatchLabelKeysInPodTopologySpread: fts.EnableMatchLabelKeysInPodTopologySpread,
    }
    // 如果 DefaultingType 为 SystemDefaulting，则使用系统默认的 TopologySpreadConstraint 列表
    if args.DefaultingType == config.SystemDefaulting {
        pl.defaultConstraints = systemDefaultConstraints
        pl.systemDefaulted = true
    }
    // 如果 defaultConstraints 不为空，就需要设置对应的 SharedInformerFactory
    if len(pl.defaultConstraints) != 0 {
        if h.SharedInformerFactory() == nil {
            return nil, fmt.Errorf("SharedInformerFactory is nil")
        }
        pl.setListers(h.SharedInformerFactory())
    }
    // 返回 PodTopologySpread 对象
    return pl, nil
}
```

```GO
// 从参数中获取 PodTopologySpreadArgs 对象
func getArgs(obj runtime.Object) (config.PodTopologySpreadArgs, error) {
    ptr, ok := obj.(*config.PodTopologySpreadArgs)
    if !ok {
        return config.PodTopologySpreadArgs{}, fmt.Errorf("want args to be of type PodTopologySpreadArgs, got %T", obj)
    }
    return *ptr, nil
}

func (pl *PodTopologySpread) setListers(factory informers.SharedInformerFactory) {
	pl.services = factory.Core().V1().Services().Lister()
	pl.replicationCtrls = factory.Core().V1().ReplicationControllers().Lister()
	pl.replicaSets = factory.Apps().V1().ReplicaSets().Lister()
	pl.statefulSets = factory.Apps().V1().StatefulSets().Lister()
}

var systemDefaultConstraints = []v1.TopologySpreadConstraint{
	{
		TopologyKey:       v1.LabelHostname,
		WhenUnsatisfiable: v1.ScheduleAnyway,
		MaxSkew:           3,
	},
	{
		TopologyKey:       v1.LabelTopologyZone,
		WhenUnsatisfiable: v1.ScheduleAnyway,
		MaxSkew:           5,
	},
}
```

### PreFilter&PreFilterExtensions

```GO
// PreFilter 在预过滤器扩展点被调用
func (pl *PodTopologySpread) PreFilter(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod) (*framework.PreFilterResult, *framework.Status) {
	// 计算预过滤状态
	s, err := pl.calPreFilterState(ctx, pod)
	if err != nil {
		return nil, framework.AsStatus(err)
	}
	// 将预过滤状态写入调度周期状态
	cycleState.Write(preFilterStateKey, s)
	// 返回 nil 表示没有被拒绝，nil 表示没有状态错误
	return nil, nil
}

// PreFilterExtensions 返回预过滤器扩展，包括添加和删除 Pod。
func (pl *PodTopologySpread) PreFilterExtensions() framework.PreFilterExtensions {
	// 返回预过滤器本身作为扩展
	return pl
}

// AddPod 从 cycleState 中预计算的数据中添加 Pod。
func (pl *PodTopologySpread) AddPod(ctx context.Context, cycleState *framework.CycleState, podToSchedule *v1.Pod, podInfoToAdd *framework.PodInfo, nodeInfo *framework.NodeInfo) *framework.Status {
    // 获取 cycleState 中预计算的状态信息
    s, err := getPreFilterState(cycleState)
    if err != nil {
        // 如果获取状态信息失败，则返回一个 framework.Status 类型的错误
        return framework.AsStatus(err)
    }
    // 使用更新节点状态的方法更新状态信息
    pl.updateWithPod(s, podInfoToAdd.Pod, podToSchedule, nodeInfo.Node(), 1)
    // 添加成功，返回 nil
    return nil
}

// RemovePod 从 cycleState 中预计算的数据中移除 Pod。
func (pl *PodTopologySpread) RemovePod(ctx context.Context, cycleState *framework.CycleState, podToSchedule *v1.Pod, podInfoToRemove *framework.PodInfo, nodeInfo *framework.NodeInfo) *framework.Status {
    // 获取 cycleState 中预计算的状态信息
    s, err := getPreFilterState(cycleState)
    if err != nil {
        // 如果获取状态信息失败，则返回一个 framework.Status 类型的错误
        return framework.AsStatus(err)
    }
    // 使用更新节点状态的方法更新状态信息
    pl.updateWithPod(s, podInfoToRemove.Pod, podToSchedule, nodeInfo.Node(), -1)
    // 移除成功，返回 nil
    return nil
}
```

#### calPreFilterState

```go
// calPreFilterState计算preFilterState，描述pod在拓扑上的分布情况。
func (pl *PodTopologySpread) calPreFilterState(ctx context.Context, pod *v1.Pod) (*preFilterState, error) {
    // 获取所有节点的NodeInfo对象。
    allNodes, err := pl.sharedLister.NodeInfos().List()
    if err != nil {
    	return nil, fmt.Errorf("listing NodeInfos: %w", err)
    }
    var constraints []topologySpreadConstraint
    // 获取pod的拓扑分散约束（topologySpreadConstraints）。
    if len(pod.Spec.TopologySpreadConstraints) > 0 {
    // APIServer有功能门控，可以过滤pod的spec，因此只需要检查Constraints的长度而不需要再次检查功能门控。
        constraints, err = pl.filterTopologySpreadConstraints(
        pod.Spec.TopologySpreadConstraints, // 拓扑分散约束
        pod.Labels,
        v1.DoNotSchedule,
    )
    if err != nil {
    	return nil, fmt.Errorf("obtaining pod's hard topology spread constraints: %w", err)
    }
    } else {
        // 如果没有定义pod的拓扑分散约束，就根据pod的特征构建默认的拓扑分散约束。
        constraints, err = pl.buildDefaultConstraints(pod, v1.DoNotSchedule)
        if err != nil {
        	return nil, fmt.Errorf("setting default hard topology spread constraints: %w", err)
        }
    }
    // 如果没有任何拓扑分散约束，则直接返回空preFilterState。
    if len(constraints) == 0 {
    	return &preFilterState{}, nil
    }
    // 初始化preFilterState。
    s := preFilterState{
        Constraints:          constraints, // 拓扑分散约束
        TpKeyToCriticalPaths: make(map[string]*criticalPaths, len(constraints)),
        TpPairToMatchNum:     make(map[topologyPair]int, sizeHeuristic(len(allNodes), constraints)),
    }

    // 统计每个节点上满足约束条件的pod数目，并存储在tpCountsByNode中。
    tpCountsByNode := make([]map[topologyPair]int, len(allNodes))
    requiredNodeAffinity := nodeaffinity.GetRequiredNodeAffinity(pod) // 获取pod所需的节点亲和性（NodeAffinity）。
    logger := klog.FromContext(ctx)
    processNode := func(i int) {
        nodeInfo := allNodes[i]
        node := nodeInfo.Node()
        if node == nil {
            logger.Error(nil, "Node not found")
            return
        }

        // 如果未开启节点包含策略，就只对通过筛选条件的节点应用分散。
        if !pl.enableNodeInclusionPolicyInPodTopologySpread {
            // 忽略解析错误以保持向后兼容性。
            if match, _ := requiredNodeAffinity.Match(node); !match {
                return
            }
        }

        // 确保当前节点的标签包含所有拓扑约束中的topologyKey。
        if !nodeLabelsMatchSpreadConstraints(node.Labels, constraints) {
            return
        }
        
         // 创建一个 map，用于记录每个拓扑对应的 Pod 数量
        tpCounts := make(map[topologyPair]int, len(constraints))
		for _, c := range constraints { // 遍历 PodTopologySpread 约束条件
			if pl.enableNodeInclusionPolicyInPodTopologySpread &&
				!c.matchNodeInclusionPolicies(pod, node, requiredNodeAffinity) {
                     // 如果开启了 Node Inclusion Policy 并且 Pod 不满足约束条件，则跳过此次循环
				continue
			}
			// 创建一个拓扑对，用于记录 pod 在哪个拓扑域上
			pair := topologyPair{key: c.TopologyKey, value: node.Labels[c.TopologyKey]}
            // 计算与 Pod 匹配的 selector 的数量
			count := countPodsMatchSelector(nodeInfo.Pods, c.Selector, pod.Namespace)
            // 将拓扑对和与之匹配的 Pod 数量存储到 tpCounts 中
			tpCounts[pair] = count
		}
        // 记录每个节点上的拓扑对和 Pod 数量的映射关系
		tpCountsByNode[i] = tpCounts
	}
    // 多线程并发执行 processNode 函数，处理所有的节点
	pl.parallelizer.Until(ctx, len(allNodes), processNode, pl.Name())

	for _, tpCounts := range tpCountsByNode {  // 遍历每个节点上的拓扑对和 Pod 数量的映射关系
        for tp, count := range tpCounts {  // 遍历拓扑对和 Pod 数量的映射关系
            s.TpPairToMatchNum[tp] += count  // 将当前拓扑对和与之匹配的 Pod 数量加到 TpPairToMatchNum 中
        }
    }
    if pl.enableMinDomainsInPodTopologySpread {  // 如果开启了最小域数的限制
        s.TpKeyToDomainsNum = make(map[string]int, len(constraints))  // 创建一个 map，用于记录每个拓扑的最小域数
        for tp := range s.TpPairToMatchNum {  // 遍历 TpPairToMatchNum
            s.TpKeyToDomainsNum[tp.key]++  // 将拓扑对的 key 添加到 TpKeyToDomainsNum 中
        }
    }

    // 计算每个拓扑对的最小匹配数
    for i := 0; i < len(constraints); i++ {
        key := constraints[i].TopologyKey
        s.TpKeyToCriticalPaths[key] = newCriticalPaths()  // 创建一个关键路径对象
    }
    for pair, num := range s.TpPairToMatchNum {  // 遍历每个拓扑对和 Pod 数量的映射关系
        s.TpKeyToCriticalPaths[pair.key].update(pair.value, num)  // 更新拓扑对的关键路径
    }

    return &s, nil  // 返回计算后的结果
}
```

##### filterTopologySpreadConstraints

```go
// 过滤并处理符合条件的拓扑约束，返回处理后的拓扑约束列表
func (pl *PodTopologySpread) filterTopologySpreadConstraints(constraints []v1.TopologySpreadConstraint, podLabels map[string]string, action v1.UnsatisfiableConstraintAction) ([]topologySpreadConstraint, error) {
    // 用于存放处理后的拓扑约束
    var result []topologySpreadConstraint
    // 遍历传入的拓扑约束列表
    for _, c := range constraints {
    // 检查该约束的不满足条件是否满足期望的动作
    if c.WhenUnsatisfiable == action {
    // 将 LabelSelector 转换为 SelectorSet 类型，为后续的 Selector 处理做准备
    selector, err := metav1.LabelSelectorAsSelector(c.LabelSelector)
    if err != nil {
        // 如果转换出错，返回错误
        return nil, err
    }
    if pl.enableMatchLabelKeysInPodTopologySpread && len(c.MatchLabelKeys) > 0 {
        // 如果启用了根据标签键匹配进行拓扑约束，且 MatchLabelKeys 不为空
        matchLabels := make(labels.Set)
        // 用于存放要匹配的标签集合
        for _, labelKey := range c.MatchLabelKeys {
            if value, ok := podLabels[labelKey]; ok {
                matchLabels[labelKey] = value
                // 将 Pod 的标签中匹配 MatchLabelKeys 中的标签键的标签加入到 matchLabels 中
            }
        }
        if len(matchLabels) > 0 {
            selector = mergeLabelSetWithSelector(matchLabels, selector)
            // 将 matchLabels 和 Selector 进行合并
        }
    }

    tsc := topologySpreadConstraint{
        MaxSkew:            c.MaxSkew,
        TopologyKey:        c.TopologyKey,
        Selector:           selector,
        MinDomains:         1,                            // 如果 MinDomains 为空，我们将其视为 1。
        NodeAffinityPolicy: v1.NodeInclusionPolicyHonor,  // 如果 NodeAffinityPolicy 为空，我们将其视为 "Honor"。
        NodeTaintsPolicy:   v1.NodeInclusionPolicyIgnore, // 如果 NodeTaintsPolicy 为空，我们将其视为 "Ignore"。
    }
    if pl.enableMinDomainsInPodTopologySpread && c.MinDomains != nil {
        tsc.MinDomains = *c.MinDomains
        // 如果启用了在 Pod 拓扑分散中的最小域计算，并且 MinDomains 不为空，则将 MinDomains 赋值给 tsc.MinDomains。
    }
    if pl.enableNodeInclusionPolicyInPodTopologySpread {
        if c.NodeAffinityPolicy != nil {
            tsc.NodeAffinityPolicy = *c.NodeAffinityPolicy
            // 如果启用了在 Pod 拓扑分散中节点亲和性的策略计算，并且 NodeAffinityPolicy 不为空，则将 NodeAffinityPolicy 赋值给 tsc.NodeAffinityPolicy。
        }
        if c.NodeTaintsPolicy != nil {
					tsc.NodeTaintsPolicy = *c.NodeTaintsPolicy
				}
			}
			result = append(result, tsc)
		}
	}
	return result, nil
}
```

##### buildDefaultConstraints

```GO
// buildDefaultConstraints 函数基于 .DefaultConstraints 和与 pod 匹配的服务、
// 复制控制器、副本集、有状态副本集的选择器构建 pod 的约束。
func (pl *PodTopologySpread) buildDefaultConstraints(p *v1.Pod, action v1.UnsatisfiableConstraintAction) ([]topologySpreadConstraint, error) {
    constraints, err := pl.filterTopologySpreadConstraints(pl.defaultConstraints, p.Labels, action)
    if err != nil || len(constraints) == 0 {
    	return nil, err
    }
    selector := helper.DefaultSelector(p, pl.services, pl.replicationCtrls, pl.replicaSets, pl.statefulSets)
    if selector.Empty() {
    	return nil, nil
    }
    for i := range constraints {
    	constraints[i].Selector = selector
    }
    return constraints, nil
}
```

##### sizeHeuristic

```GO
func sizeHeuristic(nodes int, constraints []topologySpreadConstraint) int {
    for _, c := range constraints { // 遍历所有约束
        if c.TopologyKey == v1.LabelHostname { // 如果约束为按主机名分配
            return nodes // 直接返回节点数
        }
    }
    return 0 // 否则返回 0
}
```

##### nodeLabelsMatchSpreadConstraints

```GO
// nodeLabelsMatchSpreadConstraints checks if ALL topology keys in spread Constraints are present in node labels.
func nodeLabelsMatchSpreadConstraints(nodeLabels map[string]string, constraints []topologySpreadConstraint) bool {
    for _, c := range constraints { // 遍历所有约束
        if _, ok := nodeLabels[c.TopologyKey]; !ok { // 如果节点标签中不包含当前约束的拓扑键
            return false // 直接返回 false
        }
    }
    return true // 否则返回 true
}
```

##### matchNodeInclusionPolicies

```GO
func (tsc *topologySpreadConstraint) matchNodeInclusionPolicies(pod *v1.Pod, node *v1.Node, require nodeaffinity.RequiredNodeAffinity) bool {
    if tsc.NodeAffinityPolicy == v1.NodeInclusionPolicyHonor { // 如果节点亲和性策略为必须遵守
        // 忽略此处的解析错误以保证向后兼容性
        if match, _ := require.Match(node); !match { // 检查节点是否符合亲和性要求
            return false // 如果不符合则返回 false
        }
    }

    if tsc.NodeTaintsPolicy == v1.NodeInclusionPolicyHonor { // 如果节点容忍策略为必须遵守
        if _, untolerated := v1helper.FindMatchingUntoleratedTaint(node.Spec.Taints, pod.Spec.Tolerations, helper.DoNotScheduleTaintsFilterFunc()); untolerated { // 检查 Pod 是否能够容忍当前节点上的所有污点
            return false // 如果不能，则返回 false
        }
    }
    return true // 否则返回 true
}
```

##### countPodsMatchSelector

```GO
// 用于统计符合给定标签选择器条件的 Pod 数量
func countPodsMatchSelector(podInfos []*framework.PodInfo, selector labels.Selector, ns string) int {
	// 如果标签选择器为空，则直接返回 0
	if selector.Empty() {
		return 0
	}
	// 初始化计数器为 0
	count := 0
	// 遍历 PodInfo 数组中的每一个 PodInfo
	for _, p := range podInfos {
		// 忽略正在终止的 Pod（参见 #87621）和不在给定命名空间中的 Pod
		if p.Pod.DeletionTimestamp != nil || p.Pod.Namespace != ns {
			continue
		}
		// 如果 Pod 的标签集合匹配标签选择器，则增加计数器
		if selector.Matches(labels.Set(p.Pod.Labels)) {
			count++
		}
	}
	// 返回符合条件的 Pod 数量
	return count
}
```

##### newCriticalPaths

```GO
func newCriticalPaths() *criticalPaths {
	// 创建一个 criticalPaths 结构体指针，并将其初始值设置为 {{MatchNum: math.MaxInt32}, {MatchNum: math.MaxInt32}}
	return &criticalPaths{{MatchNum: math.MaxInt32}, {MatchNum: math.MaxInt32}}
}
```

#### preFilterState

```GO
// preFilterState 是在 PreFilter 阶段计算并在 Filter 阶段使用的数据结构。
// 它将 TpKeyToCriticalPaths 和 TpPairToMatchNum 组合在一起表示：
// (1) 在每个扩散约束上匹配最少 Pod 的关键路径。
// (2) 每个扩散约束上匹配的 Pod 数量。
// nil 的 preFilterState 表示在 PreFilter 阶段根本没有设置；
// 空的 preFilterState 对象表示它是一个合法状态并且在 PreFilter 阶段被设置。
// 这些字段被导出以便在测试中进行比较。
type preFilterState struct {
    Constraints []topologySpreadConstraint
    // 这里记录了 2 条关键路径，而不是所有关键路径。
    // criticalPaths[0].MatchNum 始终保存最小匹配数量。
    // criticalPaths[1].MatchNum 始终大于或等于 criticalPaths[0].MatchNum，但是它不保证是第二小的匹配数量。
    TpKeyToCriticalPaths map[string]*criticalPaths
    // TpKeyToDomainsNum 以拓扑键为键，以域的数量为值。
    TpKeyToDomainsNum map[string]int
    // TpPairToMatchNum 以拓扑键对为键，以匹配 Pod 的数量为值。
    TpPairToMatchNum map[topologyPair]int
}
```

#### getPreFilterState

```GO
// getPreFilterState fetches a pre-computed preFilterState.
func getPreFilterState(cycleState *framework.CycleState) (*preFilterState, error) {
    c, err := cycleState.Read(preFilterStateKey) // 从 CycleState 中读取 preFilterState
    if err != nil {
        // preFilterState doesn't exist, likely PreFilter wasn't invoked.
        return nil, fmt.Errorf("reading %q from cycleState: %w", preFilterStateKey, err) // 如果不存在，说明 PreFilter 还未被调用，返回错误
    }

    s, ok := c.(*preFilterState)
    if !ok {
        return nil, fmt.Errorf("%+v convert to podtopologyspread.preFilterState error", c) // 如果读取的 preFilterState 不是期望的类型，则返回错误
    }
    return s, nil // 否则返回读取到的 preFilterState
}
```

### Filter

```GO
// 在过滤器扩展点处调用的过滤器。
func (pl *PodTopologySpread) Filter(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
    // 获取节点对象
    node := nodeInfo.Node()
    if node == nil {
    	return framework.AsStatus(fmt.Errorf("node not found"))
    }
    // 获取之前过滤器处理后的状态，如果有错误则返回错误信息
    s, err := getPreFilterState(cycleState)
    if err != nil {
        return framework.AsStatus(err)
    }

    // 但是，"empty" preFilterState 是合法的，它可以容忍要调度的每个 Pod。
    if len(s.Constraints) == 0 {
        return nil
    }

    logger := klog.FromContext(ctx)
    // 获取 Pod 的标签
    podLabelSet := labels.Set(pod.Labels)
    // 对于每个约束条件，检查是否满足
    for _, c := range s.Constraints {
        tpKey := c.TopologyKey
        // 获取节点上该拓扑域的标签值
        tpVal, ok := node.Labels[c.TopologyKey]
        if !ok {
            logger.V(5).Info("Node doesn't have required label", "node", klog.KObj(node), "label", tpKey)
            return framework.NewStatus(framework.UnschedulableAndUnresolvable, ErrReasonNodeLabelNotMatch)
        }

        // 判断标准：
        // '已有匹配数量' + '是否与自身匹配（1 或 0）' - '全局最小值' <= 'maxSkew'
        // 获取最小匹配数量和可能出现的错误
        minMatchNum, err := s.minMatchNum(tpKey, c.MinDomains, pl.enableMinDomainsInPodTopologySpread)
        if err != nil {
            logger.Error(err, "Internal error occurred while retrieving value precalculated in PreFilter", "topologyKey", tpKey, "paths", s.TpKeyToCriticalPaths)
            continue
        }

        selfMatchNum := 0
        if c.Selector.Matches(podLabelSet) {
            selfMatchNum = 1
        }

        pair := topologyPair{key: tpKey, value: tpVal}
        matchNum := 0
        if tpCount, ok := s.TpPairToMatchNum[pair]; ok {
            matchNum = tpCount
        }
        skew := matchNum + selfMatchNum - minMatchNum
        if skew > int(c.MaxSkew) {
            logger.V(5).Info("Node failed spreadConstraint: matchNum + selfMatchNum - minMatchNum > maxSkew", "node", klog.KObj(node), "topologyKey", tpKey, "matchNum", matchNum, "selfMatchNum", selfMatchNum, "minMatchNum", minMatchNum, "maxSkew", c.MaxSkew)
            return framework.NewStatus(framework.Unschedulable, ErrReasonConstraintsNotMatch)
        }
    }

    return nil
}
```

#### minMatchNum

```GO
// minMatchNum returns the global minimum for the calculation of skew while taking MinDomains into account.
func (s *preFilterState) minMatchNum(tpKey string, minDomains int32, enableMinDomainsInPodTopologySpread bool) (int, error) {
    paths, ok := s.TpKeyToCriticalPaths[tpKey] // 从 preFilterState 中获取关键路径
    if !ok {
        return 0, fmt.Errorf("failed to retrieve path by topology key") // 如果获取失败，则返回错误
    }

    minMatchNum := paths[0].MatchNum // 计算全局最小匹配数
    if !enableMinDomainsInPodTopologySpread {
        return minMatchNum, nil // 如果不考虑 MinDomains，则直接返回全局最小匹配数
    }

    domainsNum, ok := s.TpKeyToDomainsNum[tpKey] // 获取与该 topology key 匹配的域的数量
    if !ok {
        return 0, fmt.Errorf("failed to retrieve the number of domains by topology key") // 如果获取失败，则返回错误
    }

    if domainsNum < int(minDomains) {
        // 如果匹配的域的数量小于 MinDomains，则全局最小匹配数为 0
        minMatchNum = 0
    }

    return minMatchNum, nil // 返回计算得到的全局最小匹配数
}
```

### PreScore

```GO
// PreScore 函数构建并写入循环状态，该状态用于 Score 和 NormalizeScore。
func (pl *PodTopologySpread) PreScore(
ctx context.Context, // 上下文
cycleState *framework.CycleState, // 循环状态
pod *v1.Pod, // 待调度的 Pod
filteredNodes []*v1.Node, // 经过过滤后的 Node 列表
) *framework.Status {
    allNodes, err := pl.sharedLister.NodeInfos().List() // 获取所有的 Node
    if err != nil {
    	return framework.AsStatus(fmt.Errorf("getting all nodes: %w", err))
    }
    if len(filteredNodes) == 0 || len(allNodes) == 0 {
        // 没有可供评分的 Node。
        return nil
    }

    state := &preScoreState{
        IgnoredNodes:            sets.New[string](),
        TopologyPairToPodCounts: make(map[topologyPair]*int64),
    }
    // 只有在使用非系统默认的扩散规则时才需要节点具有所有拓扑标签。这允许没有区域标签的节点仍然具有主机名扩散。
    requireAllTopologies := len(pod.Spec.TopologySpreadConstraints) > 0 || !pl.systemDefaulted
    err = pl.initPreScoreState(state, pod, filteredNodes, requireAllTopologies) // 初始化 preScoreState。
    if err != nil {
        return framework.AsStatus(fmt.Errorf("calculating preScoreState: %w", err))
    }

    // 如果 incoming pod 没有 soft topology spread Constraints，则返回。
    if len(state.Constraints) == 0 {
        cycleState.Write(preScoreStateKey, state)
        return nil
    }

    // 忽略向后兼容性的解析错误。
    requiredNodeAffinity := nodeaffinity.GetRequiredNodeAffinity(pod) // 获取 Pod 所需的节点亲和性
    processAllNode := func(i int) {
        nodeInfo := allNodes[i] // 获取第 i 个 NodeInfo
        node := nodeInfo.Node()
        if node == nil {
            return
        }

        if !pl.enableNodeInclusionPolicyInPodTopologySpread {
            // `node` 应满足 incoming pod 的 NodeSelector/NodeAffinity。
            if match, _ := requiredNodeAffinity.Match(node); !match {
                return
            }
        }

        // 所有的 topologyKeys 都需要存在于 `node` 中。
        if requireAllTopologies && !nodeLabelsMatchSpreadConstraints(node.Labels, state.Constraints) {
            return
        }

        for _, c := range state.Constraints {
            if pl.enableNodeInclusionPolicyInPodTopologySpread &&
                !c.matchNodeInclusionPolicies(pod, node, requiredNodeAffinity) {
                continue
            }

            pair := topologyPair{key: c.TopologyKey, value: node.Labels[c.TopologyKey]}
            // 如果当前的拓扑对没有与任何候选节点关联，则继续以避免不必要的计算。
            // 每个节点的计数也会被跳过，因为它们在 Score 时完成。
            tpCount := state.TopologyPairToPodCounts[pair]
            if tpCount == nil {
                continue
            }
             // 计算与 Pod 匹配的 selector 的数量
            count := countPodsMatchSelector(nodeInfo.Pods, c.Selector, pod.Namespace)
			atomic.AddInt64(tpCount, int64(count))
		}
	}
    // 并发执行
	pl.parallelizer.Until(ctx, len(allNodes), processAllNode, pl.Name())

	cycleState.Write(preScoreStateKey, state)
	return nil
}
```

#### initPreScoreState

```GO
// initPreScoreState函数遍历“filteredNodes”以过滤掉不具有所需拓扑关键字的节点，并初始化：
// 1）s.TopologyPairToPodCounts：以符合条件的拓扑对和节点名称为键。
// 2）s.IgnoredNodes：不应得分的节点集合。
// 3）s.TopologyNormalizingWeight：基于拓扑中值的数量为每个约束赋予的权重。
func (pl *PodTopologySpread) initPreScoreState(s *preScoreState, pod *v1.Pod, filteredNodes []*v1.Node, requireAllTopologies bool) error {
    // 初始化Constraints，包含要匹配的拓扑限制条件。
    var err error
    if len(pod.Spec.TopologySpreadConstraints) > 0 {
        s.Constraints, err = pl.filterTopologySpreadConstraints(
            pod.Spec.TopologySpreadConstraints,
            pod.Labels,
            v1.ScheduleAnyway,
        )
        if err != nil {
        	return fmt.Errorf("obtaining pod's soft topology spread constraints: %w", err)
        }
    } else {
    	s.Constraints, err = pl.buildDefaultConstraints(pod, v1.ScheduleAnyway)
        if err != nil {
        	return fmt.Errorf("setting default soft topology spread constraints: %w", err)
        }
    }
    // 如果没有需要匹配的拓扑限制条件，则返回nil。
    if len(s.Constraints) == 0 {
        return nil
    }

    // 计算要匹配的拓扑限制条件的大小，以及符合条件的节点的数量。
    topoSize := make([]int, len(s.Constraints))
    for _, node := range filteredNodes {
        if requireAllTopologies && !nodeLabelsMatchSpreadConstraints(node.Labels, s.Constraints) {
            // 当后续进行评分时，没有所有所需的拓扑关键字的节点将被忽略。
            s.IgnoredNodes.Insert(node.Name)
            continue
        }
        for i, constraint := range s.Constraints {
            // 每个节点的计数在Score中进行计算。
            if constraint.TopologyKey == v1.LabelHostname {
                continue
            }
            pair := topologyPair{key: constraint.TopologyKey, value: node.Labels[constraint.TopologyKey]}
            if s.TopologyPairToPodCounts[pair] == nil {
                s.TopologyPairToPodCounts[pair] = new(int64)
                topoSize[i]++
            }
        }
    }

    // 计算每个拓扑限制条件的权重。
    s.TopologyNormalizingWeight = make([]float64, len(s.Constraints))
    for i, c := range s.Constraints {
        sz := topoSize[i]
        if c.TopologyKey == v1.LabelHostname {
            sz = len(filteredNodes) - len(s.IgnoredNodes)
        }
        s.TopologyNormalizingWeight[i] = topologyNormalizingWeight(sz)
    }
    return nil
}
```

##### topologyNormalizingWeight

```GO
// topologyNormalizingWeight 计算拓扑结构的权重，基于拓扑结构中存在的值的数量。
// 由于<size>至少为1（通过筛选的所有节点都在相同的拓扑结构中），且k8s支持5k个节点，
// 因此结果在区间<1.09，8.52>之间。
//
// 注意: 当没有节点具有所需的拓扑结构时，<size>也可能为零，
// 但是我们在这种情况下不关心拓扑权重，因为我们为所有节点返回0分。
func topologyNormalizingWeight(size int) float64 {
	return math.Log(float64(size + 2))
}
```

#### preScoreState

```GO
// preScoreState 在 PreScore 阶段计算，在 Score 阶段使用。
// Fields are exported for comparison during testing.
type preScoreState struct {
    Constraints []topologySpreadConstraint
    // IgnoredNodes 是一个节点名称的集合，它缺少一些 Constraints[*].topologyKey。
    IgnoredNodes sets.Set[string]
    // TopologyPairToPodCounts 键入 topologyPair，其值为匹配的 Pod 数量。
    TopologyPairToPodCounts map[topologyPair]*int64
    // TopologyNormalizingWeight 是我们给予每个拓扑的权重。
    // 这允许较小拓扑的 Pod 数量不被较大拓扑所稀释。
    TopologyNormalizingWeight []float64
}
```

### Score&ScoreExtensions

```GO
// Score 函数会在 Score 扩展点调用。
// 函数返回的 "score" 是在 `nodeName` 上匹配的 Pod 数量，稍后会进行规范化。
func (pl *PodTopologySpread) Score(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, nodeName string) (int64, *framework.Status) {
	// 获取 nodeName 对应的 NodeInfo
	nodeInfo, err := pl.sharedLister.NodeInfos().Get(nodeName)
	if err != nil {
		return 0, framework.AsStatus(fmt.Errorf("getting node %q from Snapshot: %w", nodeName, err))
	}

	// 获取 Node 对象和 ScoreState 对象
	node := nodeInfo.Node()
	s, err := getPreScoreState(cycleState)
	if err != nil {
		return 0, framework.AsStatus(err)
	}

	// 如果节点不符合要求，直接返回 0
	if s.IgnoredNodes.Has(node.Name) {
		return 0, nil
	}

	// 对于每个存在的 <pair>，当前节点都会得到 <matchSum> 的信用。
	// 最终将所有 <matchSum> 相加并返回作为该节点的得分。
	var score float64
	for i, c := range s.Constraints {
		if tpVal, ok := node.Labels[c.TopologyKey]; ok {
			var cnt int64
			if c.TopologyKey == v1.LabelHostname {
				// 如果 topologyKey 是 hostname，则通过 countPodsMatchSelector 函数计算匹配 Pod 数量。
				cnt = int64(countPodsMatchSelector(nodeInfo.Pods, c.Selector, pod.Namespace))
			} else {
				// 如果 topologyKey 不是 hostname，则获取对应的 topologyPair，通过 TopologyPairToPodCounts 映射获取匹配 Pod 数量。
				pair := topologyPair{key: c.TopologyKey, value: tpVal}
				cnt = *s.TopologyPairToPodCounts[pair]
			}
			// 根据匹配 Pod 数量、最大偏差值和 topologyNormalizingWeight 计算当前 topologyKey 对当前节点的得分贡献。
			score += scoreForCount(cnt, c.MaxSkew, s.TopologyNormalizingWeight[i])
		}
	}
	// 对得分进行四舍五入并返回。
	return int64(math.Round(score)), nil
}

// ScoreExtensions of the Score plugin.
// ScoreExtensions 函数返回 Score 插件自身。
func (pl *PodTopologySpread) ScoreExtensions() framework.ScoreExtensions {
	return pl
}

// NormalizeScore 方法在对所有节点进行打分后调用。
func (pl *PodTopologySpread) NormalizeScore(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, scores framework.NodeScoreList) *framework.Status {
    // 获取 getPreScoreState 返回的 s 和可能发生的错误。
    s, err := getPreScoreState(cycleState)
    if err != nil {
    	return framework.AsStatus(err)
    }
    if s == nil {
    	return nil
    }
    // 计算 <minScore> 和 <maxScore>。
    var minScore int64 = math.MaxInt64
    var maxScore int64
    for i, score := range scores {
        // 必须检查 score.Name 是否在 IgnoredNodes 中。
        if s.IgnoredNodes.Has(score.Name) {
            scores[i].Score = invalidScore
            continue
        }
        if score.Score < minScore {
            minScore = score.Score
        }
        if score.Score > maxScore {
            maxScore = score.Score
        }
    }

    // 根据 <minScore> 和 <maxScore> 对所有得分进行归一化。
    for i := range scores {
        if scores[i].Score == invalidScore {
            scores[i].Score = 0
            continue
        }
        if maxScore == 0 {
            scores[i].Score = framework.MaxNodeScore
            continue
        }
        s := scores[i].Score
        scores[i].Score = framework.MaxNodeScore * (maxScore + minScore - s) / maxScore
    }
    return nil
}
```

#### getPreScoreState

```GO
func getPreScoreState(cycleState *framework.CycleState) (*preScoreState, error) {
	c, err := cycleState.Read(preScoreStateKey)
	if err != nil {
		return nil, fmt.Errorf("error reading %q from cycleState: %w", preScoreStateKey, err)
	}

	s, ok := c.(*preScoreState)
	if !ok {
		return nil, fmt.Errorf("%+v  convert to podtopologyspread.preScoreState error", c)
	}
	return s, nil
}
```

#### scoreForCount

```GO
// scoreForCount 函数基于拓扑域中匹配 pod 数量、约束的 maxSkew 和拓扑权重计算得分。
// maxSkew-1 被添加到得分中，以便减轻拓扑域之间的差异，控制得分对偏差的容忍度。
func scoreForCount(cnt int64, maxSkew int32, tpWeight float64) float64 {
	return float64(cnt)*tpWeight + float64(maxSkew-1)
}
```

### PodTopologySpread

```GO
// EventsToRegister 返回可能使由该插件导致的 Pod 失败的事件可调度。
func (pl *PodTopologySpread) EventsToRegister() []framework.ClusterEvent {
	return []framework.ClusterEvent{
        // ActionType 包括以下事件：
        // - Add. 一个无法调度的 Pod 可能由于违反拓扑传播约束而失败，
        // 添加一个已分配的 Pod 可能使其可调度。
        // - Update. 更新现有 Pod 的标签（例如，删除标签）可能会使一个无法调度的 Pod 可调度。
        // - Delete. 一个无法调度的 Pod 可能由于违反现有 Pod 的拓扑传播约束而失败，
        // 删除现有 Pod 可能使其可调度。
        {Resource: framework.Pod, ActionType: framework.All},
        // Node add|delete|updateLabel 可能导致拓扑键发生更改，
        // 并使这些 Pod 在调度时可调度或不可调度。
        {Resource: framework.Node, ActionType: framework.Add | framework.Delete | framework.UpdateNodeLabel},
	}
```

## SchedulingGates

### 作用

Kubernetes中的SchedulingGates插件是一个Beta级别的插件，它允许用户为Pods设置条件，在这些条件满足之前，这些Pods将不会被调度到节点上。这个插件可以帮助用户实现一些高级调度策略，比如等待资源的可用性或者等待其他Pods完成等。

### 结构

```GO
// 插件在插件注册表和配置中的名称
const Name = names.SchedulingGates

// SchedulingGates 检查一个 Pod 是否携带 .spec.schedulingGates
type SchedulingGates struct {
	enablePodSchedulingReadiness bool
}

// 确保 SchedulingGates 实现了 PreEnqueuePlugin 和 EnqueueExtensions 接口
var _ framework.PreEnqueuePlugin = &SchedulingGates{}
var _ framework.EnqueueExtensions = &SchedulingGates{}

// 返回插件的名称
func (pl *SchedulingGates) Name() string {
	return Name
}

// 初始化一个新的插件并返回它
func New(_ runtime.Object, _ framework.Handle, fts feature.Features) (framework.Plugin, error) {
	return &SchedulingGates{enablePodSchedulingReadiness: fts.EnablePodSchedulingReadiness}, nil
}
```

### PreEnqueue

```GO
// 定义函数 PreEnqueue，它属于类型 SchedulingGates 的方法，接收一个 context.Context 类型的上下文对象和一个 *v1.Pod 类型的指针作为参数，返回一个 *framework.Status 类型的指针。
func (pl *SchedulingGates) PreEnqueue(ctx context.Context, p *v1.Pod) *framework.Status {
    // 如果不开启 Pod 调度准备状态检查或者 Pod 的 SchedulingGates 字段为空，则直接返回 nil。
    if !pl.enablePodSchedulingReadiness || len(p.Spec.SchedulingGates) == 0 {
    	return nil
    }
    // 定义一个字符串类型的数组 gates，用于存储 Pod 的 SchedulingGates 名称。
    var gates []string
    // 遍历 Pod 的 SchedulingGates，将每个 SchedulingGates 的名称添加到 gates 数组中。
    for _, gate := range p.Spec.SchedulingGates {
    	gates = append(gates, gate.Name)
    }
    // 返回一个 *framework.Status 类型的指针，状态为 UnschedulableAndUnresolvable，消息内容为等待调度门：gates。
    return framework.NewStatus(framework.UnschedulableAndUnresolvable, fmt.Sprintf("waiting for scheduling gates: %v", gates))
    }
}
```

### EventsToRegister

```GO
// 定义函数 EventsToRegister，它属于类型 SchedulingGates 的方法，返回一个 framework.ClusterEvent 类型的切片。
func (pl *SchedulingGates) EventsToRegister() []framework.ClusterEvent {
    // 返回一个 framework.ClusterEvent 类型的切片，其中仅包含一个元素，元素的 Resource 字段为 framework.Pod，ActionType 字段为 framework.Update。
    return []framework.ClusterEvent{
    	{Resource: framework.Pod, ActionType: framework.Update},
    }
}
```

## SelectorSpread

### 作用

将Pods均匀地分布在集群中的节点上，以避免单个节点上负载过重，而其他节点却处于空闲状态的情况。这个插件可以帮助用户实现负载均衡的目标，从而提高整个集群的稳定性和可靠性。

当用户创建一个Deployment、StatefulSet或者ReplicaSet时，SelectorSpread插件会根据用户指定的Pod标签选择器，计算每个节点上已经存在的、符合条件的Pod数量，并将新的Pod尽可能分布到数量较少的节点上。这个计算过程基于节点的资源利用率，以及Pod之间的亲和性和反亲和性，可以通过配置调整插件的行为。

需要注意的是，SelectorSpread插件并不考虑节点的硬件配置、网络延迟和距离等因素，因此在一些特殊的场景下，可能会出现节点之间负载不均衡的情况。在这种情况下，用户可以考虑使用其他的调度插件，或者手动指定Pod的节点亲和性和反亲和性，以实现更精细的调度策略。

### 结构

```GO
// SelectorSpread 是一个计算选择器分散优先级的插件。
type SelectorSpread struct {
    sharedLister framework.SharedLister // 共享的列表查询器，用于查询集群中的对象。
    services corelisters.ServiceLister // Service 列表查询器，用于查询 Service 对象。
    replicationControllers corelisters.ReplicationControllerLister // ReplicationController 列表查询器，用于查询 ReplicationController 对象。
    replicaSets appslisters.ReplicaSetLister // ReplicaSet 列表查询器，用于查询 ReplicaSet 对象。
    statefulSets appslisters.StatefulSetLister // StatefulSet 列表查询器，用于查询 StatefulSet 对象。
}

// 验证 SelectorSpread 实现了 framework.PreScorePlugin 接口。
var _ framework.PreScorePlugin = &SelectorSpread{}
// 验证 SelectorSpread 实现了 framework.ScorePlugin 接口。
var _ framework.ScorePlugin = &SelectorSpread{}

// 声明 Name 常量，表示插件名称。
const Name = names.SelectorSpread

// Name 返回插件的名称。
func (pl *SelectorSpread) Name() string {
	return Name
}

// New 初始化一个新的 SelectorSpread 插件并返回它。
func New(_ runtime.Object, handle framework.Handle) (framework.Plugin, error) {
    // 获取共享列表查询器。
    sharedLister := handle.SnapshotSharedLister()
    if sharedLister == nil {
   		return nil, fmt.Errorf("SnapshotSharedLister is nil")
    }
    // 获取共享信息工厂。
    sharedInformerFactory := handle.SharedInformerFactory()
    if sharedInformerFactory == nil {
    	return nil, fmt.Errorf("SharedInformerFactory is nil")
    }
    // 返回一个 SelectorSpread 实例。
    return &SelectorSpread{
        sharedLister: sharedLister,
        services: sharedInformerFactory.Core().V1().Services().Lister(),
        replicationControllers: sharedInformerFactory.Core().V1().ReplicationControllers().Lister(),
        replicaSets: sharedInformerFactory.Apps().V1().ReplicaSets().Lister(),
        statefulSets: sharedInformerFactory.Apps().V1().StatefulSets().Lister(),
    }, nil
}
```

### PreScore

```GO
// PreScore 函数用于构建并写入由 Score 和 NormalizeScore 使用的周期状态。
func (pl *SelectorSpread) PreScore(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, nodes []*v1.Node) *framework.Status {
    // 如果 pod 不需要 SelectorSpread，则直接返回 nil。
    if skipSelectorSpread(pod) {
    	return nil
    }
    // 获取 Pod 的选择器，使用 pl 中的 services、replicationControllers、replicaSets、statefulSets 进行筛选。
    selector := helper.DefaultSelector(
        pod,
        pl.services,
        pl.replicationControllers,
        pl.replicaSets,
        pl.statefulSets,
    )
    // 构建 preScoreState 实例并写入 cycleState。
    state := &preScoreState{
    	selector: selector,
    }
    cycleState.Write(preScoreStateKey, state)
    return nil
}
```

#### skipSelectorSpread

```GO
// 如果 Pod 的 TopologySpreadConstraints 指定了，返回 true。
// 注意，这不考虑为 PodTopologySpread 插件定义的默认约束。
func skipSelectorSpread(pod *v1.Pod) bool {
	return len(pod.Spec.TopologySpreadConstraints) != 0
}
```

#### preScoreState

````GO
// preScoreState 在 PreScore 时计算并在 Score 时使用。
type preScoreState struct {
	selector labels.Selector
}
````

#### DefaultSelector

```GO
// DefaultSelector 函数返回一个从 Services、Replication Controllers、Replica Sets 和 Stateful Sets 中匹配给定 pod 的选择器。
func DefaultSelector(
    pod *v1.Pod,
    sl corelisters.ServiceLister,
    cl corelisters.ReplicationControllerLister,
    rsl appslisters.ReplicaSetLister,
    ssl appslisters.StatefulSetLister,
) labels.Selector {
    // 创建一个 labelSet，用于存储筛选出的标签集合。
    labelSet := make(labels.Set)
    // 通过给定的 ServiceLister 和 Pod 获取匹配的服务，然后将服务的选择器与 labelSet 合并。
    if services, err := GetPodServices(sl, pod); err == nil {
        for _, service := range services {
            labelSet = labels.Merge(labelSet, service.Spec.Selector)
        }
    }
    selector := labelSet.AsSelector()

    // 获取 Pod 所属的 owner
    owner := metav1.GetControllerOfNoCopy(pod)
    if owner == nil {
        return selector
    }

    // 解析 owner 的 GroupVersion 和 Kind
    gv, err := schema.ParseGroupVersion(owner.APIVersion)
    if err != nil {
        return selector
    }
    gvk := gv.WithKind(owner.Kind)

    // 根据 owner 的 Kind 进行不同的处理
    switch gvk {
    case rcKind:
        // 如果 owner 是 Replication Controller，则获取其 Selector 并将其与 labelSet 合并。
        if rc, err := cl.ReplicationControllers(pod.Namespace).Get(owner.Name); err == nil {
            labelSet = labels.Merge(labelSet, rc.Spec.Selector)
            selector = labelSet.AsSelector()
        }
    case rsKind:
        // 如果 owner 是 Replica Set，则将 Replica Set 的 Selector 转换为 Requirements，并将其添加到 selector 中。
        if rs, err := rsl.ReplicaSets(pod.Namespace).Get(owner.Name); err == nil {
            if other, err := metav1.LabelSelectorAsSelector(rs.Spec.Selector); err == nil {
                if r, ok := other.Requirements(); ok {
                    selector = selector.Add(r...)
                }
            }
        }
    case ssKind:
        // 如果 owner 是 Stateful Set，则将 Stateful Set 的 Selector 转换为 Requirements，并将其添加到 selector 中。
        if ss, err := ssl.StatefulSets(pod.Namespace).Get(owner.Name); err == nil {
            if other, err := metav1.LabelSelectorAsSelector(ss.Spec.Selector); err == nil {
                if r, ok := other.Requirements(); ok {
                    selector = selector.Add(r...)
                }
            }
        }
    default:
        // 如果 owner 不是支持的控制器，则直接返回 selector。
    }

    return selector
}
```

##### GetPodServices

```GO
// GetPodServices函数获取具有与给定Pod标签匹配选择器的服务。
func GetPodServices(sl corelisters.ServiceLister, pod *v1.Pod) ([]*v1.Service, error) {
    // 通过 ServiceLister 获取 Pod 命名空间中的所有 Service
    allServices, err := sl.Services(pod.Namespace).List(labels.Everything())
    if err != nil {
    	return nil, err
    }
    // 创建一个服务列表
    var services []*v1.Service

    // 遍历所有服务
    for i := range allServices {
        // 获取当前服务
        service := allServices[i]

        // 如果当前服务的选择器为空，则不进行匹配
        if service.Spec.Selector == nil {
            // services with nil selectors match nothing, not everything.
            continue
        }

        // 根据服务的选择器创建一个预先验证过的选择器
        selector := labels.Set(service.Spec.Selector).AsSelectorPreValidated()

        // 如果 Pod 的标签与服务的选择器匹配，则将该服务添加到服务列表中
        if selector.Matches(labels.Set(pod.Labels)) {
            services = append(services, service)
        }
    }

    // 返回服务列表和错误（如果有）
    return services, nil
}
```

### Score&ScoreExtensions

```GO
// 在 Score 扩展点中调用 Score 方法。
// 此函数返回的 "score" 是 nodeName 上匹配 pod 数量，稍后将进行归一化。
func (pl *SelectorSpread) Score(ctx context.Context, state *framework.CycleState, pod *v1.Pod, nodeName string) (int64, *framework.Status) {
    // 如果 pod 符合跳过 selector spread 的条件，则返回 0。
    if skipSelectorSpread(pod) {
    	return 0, nil
    }
	// 从 CycleState 中读取预处理的状态。
    c, err := state.Read(preScoreStateKey)
    if err != nil {
        return 0, framework.AsStatus(fmt.Errorf("reading %q from cycleState: %w", preScoreStateKey, err))
    }

    // 将读取到的状态转换为预处理状态。
    s, ok := c.(*preScoreState)
    if !ok {
        return 0, framework.AsStatus(fmt.Errorf("cannot convert saved state to selectorspread.preScoreState"))
    }

    // 从 sharedLister 中获取 nodeName 对应的 NodeInfo。
    nodeInfo, err := pl.sharedLister.NodeInfos().Get(nodeName)
    if err != nil {
        return 0, framework.AsStatus(fmt.Errorf("getting node %q from Snapshot: %w", nodeName, err))
    }

    // 计算匹配 nodeName 上 pod 的数量。
    count := countMatchingPods(pod.Namespace, s.selector, nodeInfo)
    return int64(count), nil
}

func (pl *SelectorSpread) ScoreExtensions() framework.ScoreExtensions {
	return pl
}

// NormalizeScore 在对所有节点进行打分后调用。
// 对于这个插件，它根据节点上现有的匹配 pod 数量计算每个节点的得分，
// 在包含区域信息的节点上，它会优先选择已存在较少匹配 pod 的区域中的节点。
func (pl *SelectorSpread) NormalizeScore(ctx context.Context, state *framework.CycleState, pod *v1.Pod, scores framework.NodeScoreList) *framework.Status {
    // 如果 Pod 不需要 SelectorSpread，则直接返回。
    if skipSelectorSpread(pod) {
    	return nil
    }
    // 用于存储每个区域中匹配 Pod 的数量。
    countsByZone := make(map[string]int64, 10)
    // 区域中匹配 Pod 数量的最大值。
    maxCountByZone := int64(0)
    // 节点中匹配 Pod 数量的最大值。
    maxCountByNodeName := int64(0)

    // 遍历节点得分列表，找到节点中匹配 Pod 数量的最大值和每个区域中匹配 Pod 的数量。
    for i := range scores {
        if scores[i].Score > maxCountByNodeName {
            maxCountByNodeName = scores[i].Score
        }
        nodeInfo, err := pl.sharedLister.NodeInfos().Get(scores[i].Name)
        if err != nil {
            return framework.AsStatus(fmt.Errorf("getting node %q from Snapshot: %w", scores[i].Name, err))
        }
        // 获取节点所在的区域。
        zoneID := utilnode.GetZoneKey(nodeInfo.Node())
        if zoneID == "" {
            continue
        }
        countsByZone[zoneID] += scores[i].Score
    }

    // 找到每个区域中匹配 Pod 数量的最大值。
    for zoneID := range countsByZone {
        if countsByZone[zoneID] > maxCountByZone {
            maxCountByZone = countsByZone[zoneID]
        }
    }

    // 是否有区域信息。
    haveZones := len(countsByZone) != 0

    // 强制转换为 float64。
    maxCountByNodeNameFloat64 := float64(maxCountByNodeName)
    maxCountByZoneFloat64 := float64(maxCountByZone)
    MaxNodeScoreFloat64 := float64(framework.MaxNodeScore)

    // 遍历节点得分列表，计算每个节点的得分。
    for i := range scores {
        // 初始化为默认的最大节点得分。
        fScore := MaxNodeScoreFloat64
        if maxCountByNodeName > 0 {
            fScore = MaxNodeScoreFloat64 * (float64(maxCountByNodeName-scores[i].Score) / maxCountByNodeNameFloat64)
        }
        // 如果有区域信息，则将其纳入计算。
        if haveZones {
            nodeInfo, err := pl.sharedLister.NodeInfos().Get(scores[i].Name)
            if err != nil {
                return framework.AsStatus(fmt.Errorf("getting node %q from Snapshot: %w", scores[i].Name, err))
            }

            // 获取节点所在的区域。
            zoneID := utilnode.GetZoneKey(nodeInfo.Node())
            if zoneID != "" {
                // 如果存在区域ID，则将区域得分考虑进去
				zoneScore := MaxNodeScoreFloat64
                // 如果最大区域计数大于零
				if maxCountByZone > 0 {
                    // 根据现有区域匹配数(countsByZone[zoneID])计算出区域得分。
					zoneScore = MaxNodeScoreFloat64 * (float64(maxCountByZone-countsByZone[zoneID]) / maxCountByZoneFloat64)
				}
                // 计算完成后，将区域权重(zoneWeighting)应用于节点分数(fScore)
				fScore = (fScore * (1.0 - zoneWeighting)) + (zoneWeighting * zoneScore)
			}
		}
        // 保存分数
		scores[i].Score = int64(fScore)
	}
	return nil
}
```

#### countMatchingPods

```GO
// countMatchingPods 根据命名空间和匹配所有选择器来计算 pod 数量。
func countMatchingPods(namespace string, selector labels.Selector, nodeInfo *framework.NodeInfo) int {
    // 如果 nodeInfo 中没有 pod，或者 selector 为空，则返回 0。
    if len(nodeInfo.Pods) == 0 || selector.Empty() {
    	return 0
    }
    count := 0
    for _, p := range nodeInfo.Pods {
        // 忽略正在删除的 pod 以进行扩散（与 SelectorSpreadPriority 中的处理方式类似）。
        if namespace == p.Pod.Namespace && p.Pod.DeletionTimestamp == nil {
            // 如果 pod 的标签与 selector 匹配，则 count 加一。
            if selector.Matches(labels.Set(p.Pod.Labels)) {
            	count++
            }
        }
    }
    return count
}
```

