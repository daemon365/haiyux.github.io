---
title: "podautoscaler-controller 代码走读"
subtitle:
date: 2023-04-05T19:05:41+08:00
draft: false
toc: true
categories: 
  - cloud
tags: 
  - kubernetes
  - controller
authors:
    - haiyux
# featuredImagePreview: /img/preview/controller/podautoscaler-controller.jpg
---

## 简介

Kubernetes  是一个开源的容器编排系统，可以自动化部署、扩展和管理容器化应用程序。在 Kubernetes 中，Pod 是最小的可部署对象，可以包含一个或多个容器。

Pod Autoscaler Controller 是 Kubernetes 的一个控制器，用于自动缩放 Pod 的数量。Pod Autoscaler Controller 监测指定的 Kubernetes 资源（例如 Deployment、ReplicaSet 或 StatefulSet）中的 CPU 使用率或自定义指标，并根据预定义的规则自动增加或减少 Pod 的数量。这可以确保应用程序具有所需的计算资源，而不会过度或低估分配。

Pod Autoscaler Controller 作为 Kubernetes 的一个重要组件，可以使应用程序更具弹性和稳定性，同时可以更好地利用资源，降低成本和提高效率。

## 结构体

```GO
type HorizontalController struct {
    // 与 Kubernetes API 服务器通信获取自动扩展目标资源对象的度量客户端
	scaleNamespacer scaleclient.ScalesGetter
    // 与 Kubernetes API 服务器通信获取水平自动扩展对象
	hpaNamespacer   autoscalingclient.HorizontalPodAutoscalersGetter
    // 管理 Kubernetes API 资源和 REST 端点之间的映射
	mapper          apimeta.RESTMapper
	// 用于计算目标 Pod 数量的 ReplicaCalculator 对象
	replicaCalc   *ReplicaCalculator
    // 记录事件的记录器
	eventRecorder record.EventRecorder
	// 在缩小容器数量时，为了避免过于频繁的缩小操作而添加的稳定时间窗口
	downscaleStabilisationWindow time.Duration
	// 监视节点的资源使用率
	monitor monitor.Monitor

	// HPA对象Lister
	hpaLister       autoscalinglisters.HorizontalPodAutoscalerLister
	hpaListerSynced cache.InformerSynced

	// pod对象Lister
	podLister       corelisters.PodLister
	podListerSynced cache.InformerSynced

	// 同步需要更新的 HPA 控制器的工作队列
	queue workqueue.RateLimitingInterface

	// 最新的未稳定推荐，以每个自动扩展器为键的字典
	recommendations     map[string][]timestampedRecommendation
    // 保护 recommendations
	recommendationsLock sync.Mutex

	// 最新的自动扩展事件，用于增加容器数量
	scaleUpEvents       map[string][]timestampedScaleEvent
    // 保护 scaleUpEvents
	scaleUpEventsLock   sync.RWMutex
    // 最新的自动扩展事件，用于减少容器数量
	scaleDownEvents     map[string][]timestampedScaleEvent
	// 保护 scaleDownEvents
	scaleDownEventsLock sync.RWMutex

	// 存储 HPA 和其选择器的双向多对多映射
	hpaSelectors    *selectors.BiMultimap
    // 保护 hpaSelectors 
	hpaSelectorsMux sync.Mutex

	// 一个特性标记，指示是否启用容器资源指标
	containerResourceMetricsEnabled bool
}

```

## MetricsClient

```GO
type MetricsClient interface {
	// 获取指定命名空间中匹配指定选择器的所有 Pod 的指定容器的给定资源度量值，如果 container 参数为空字符串，则返回所有容器度量值的总和。
	GetResourceMetric(ctx context.Context, resource v1.ResourceName, namespace string, selector labels.Selector, container string) (PodMetricsInfo, time.Time, error)

	// 获取指定命名空间中匹配指定选择器的所有 Pod 的指定度量值及其最早时间戳
	GetRawMetric(metricName string, namespace string, selector labels.Selector, metricSelector labels.Selector) (PodMetricsInfo, time.Time, error)

	// 获取给定命名空间中指定对象的给定度量值及其时间戳
	GetObjectMetric(metricName string, namespace string, objectRef *autoscaling.CrossVersionObjectReference, metricSelector labels.Selector) (int64, time.Time, error)

	// 获取与指定选择器匹配的给定外部度量值的所有值
	GetExternalMetric(metricName string, namespace string, selector labels.Selector) ([]int64, time.Time, error)
}

type PodMetric struct {
	Timestamp time.Time
	Window    time.Duration
	Value     int64
}

// PodMetricsInfo包含pod度量，作为从pod名称到PodMetrics信息的映射
type PodMetricsInfo map[string]PodMetric
```

### restMetricsClient

```GO
type restMetricsClient struct {
	*resourceMetricsClient
	*customMetricsClient
	*externalMetricsClient
}
```

#### New

```go
func NewRESTMetricsClient(resourceClient resourceclient.PodMetricsesGetter, customClient customclient.CustomMetricsClient, externalClient externalclient.ExternalMetricsClient) MetricsClient {
	return &restMetricsClient{
		&resourceMetricsClient{resourceClient},
		&customMetricsClient{customClient},
		&externalMetricsClient{externalClient},
	}
}
```

### resourceMetricsClient

```GO
type resourceMetricsClient struct {
    // 获得 Kubernetes 核心资源度量值 可以用来获取 Pod、节点和命名空间的 CPU 和内存使用情况等度量值信息
	client resourceclient.PodMetricsesGetter
}
```

#### GetResourceMetric

```go
func (c *resourceMetricsClient) GetResourceMetric(ctx context.Context, resource v1.ResourceName, namespace string, selector labels.Selector, container string) (PodMetricsInfo, time.Time, error) {
	// 从 API 服务器获取 Pod 的度量值
	metrics, err := c.client.PodMetricses(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		// 如果出现错误，返回错误信息
		return nil, time.Time{}, fmt.Errorf("unable to fetch metrics from resource metrics API: %v", err)
	}

	// 如果没有获取到 Pod 的度量值，返回错误信息
	if len(metrics.Items) == 0 {
		return nil, time.Time{}, fmt.Errorf("no metrics returned from resource metrics API")
	}

	var res PodMetricsInfo
	// 如果 container 参数不为空，则获取容器的度量值
	if container != "" {
		res, err = getContainerMetrics(metrics.Items, resource, container)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("failed to get container metrics: %v", err)
		}
	} else {
		// 否则获取 Pod 的度量值
		res = getPodMetrics(ctx, metrics.Items, resource)
	}
	// 获取最新的时间戳
	timestamp := metrics.Items[0].Timestamp.Time
	return res, timestamp, nil
}

```

##### getContainerMetrics

```GO
func getContainerMetrics(rawMetrics []metricsapi.PodMetrics, resource v1.ResourceName, container string) (PodMetricsInfo, error) {
	// 使用make函数创建一个PodMetricsInfo类型的map，长度为rawMetrics的长度
	res := make(PodMetricsInfo, len(rawMetrics))
	// 遍历rawMetrics的每一个元素，使用_占位符忽略索引，m为rawMetrics的元素值
	for _, m := range rawMetrics {
		// 定义一个变量containerFound并初始化为false
		containerFound := false
		// 遍历m.Containers的每一个元素，使用_占位符忽略索引，c为m.Containers的元素值
		for _, c := range m.Containers {
			// 如果c.Name等于传入的container参数，将containerFound设为true
			if c.Name == container {
				containerFound = true
				// 如果c.Usage[resource]存在，则将值存储在val中，将resFound设为true
				if val, resFound := c.Usage[resource]; resFound {
					// 将PodMetric结构体赋值给res[m.Name]，其中Timestamp字段为m.Timestamp.Time，Window字段为m.Window.Duration，Value字段为val.MilliValue()
					res[m.Name] = PodMetric{
						Timestamp: m.Timestamp.Time,
						Window:    m.Window.Duration,
						Value:     val.MilliValue(),
					}
				}
				// 跳出循环
				break
			}
		}
		// 如果containerFound为false，返回nil和一个格式化的错误，提示container参数在m的namespace和name中不存在
		if !containerFound {
			return nil, fmt.Errorf("container %s not present in metrics for pod %s/%s", container, m.Namespace, m.Name)
		}
	}
	// 返回res和nil
	return res, nil
}

```

##### getPodMetrics

```GO
func getPodMetrics(ctx context.Context, rawMetrics []metricsapi.PodMetrics, resource v1.ResourceName) PodMetricsInfo {
	// 使用make函数创建一个PodMetricsInfo类型的map，长度为rawMetrics的长度
	res := make(PodMetricsInfo, len(rawMetrics))
	// 遍历rawMetrics的每一个元素，使用_占位符忽略索引，m为rawMetrics的元素值
	for _, m := range rawMetrics {
		// 定义一个变量podSum并初始化为0，missing初始化为true
		podSum := int64(0)
		missing := len(m.Containers) == 0
		// 遍历m.Containers的每一个元素，使用_占位符忽略索引，c为m.Containers的元素值
		for _, c := range m.Containers {
			// 如果c.Usage[resource]不存在，将missing设为true，输出日志并跳出循环
			resValue, found := c.Usage[resource]
			if !found {
				missing = true
				klog.FromContext(ctx).V(2).Info("Missing resource metric", "resourceMetric", resource, "pod", klog.KRef(m.Namespace, m.Name))
				break
			}
			// 将c.Usage[resource]的MilliValue加到podSum上
			podSum += resValue.MilliValue()
		}
		// 如果missing为false，则将PodMetric结构体赋值给res[m.Name]，其中Timestamp字段为m.Timestamp.Time，Window字段为m.Window.Duration，Value字段为podSum
		if !missing {
			res[m.Name] = PodMetric{
				Timestamp: m.Timestamp.Time,
				Window:    m.Window.Duration,
				Value:     podSum,
			}
		}
	}
	// 返回res
	return res
}

```

### customMetricsClient

```GO
type customMetricsClient struct {
	client customclient.CustomMetricsClient
}
```

#### GetRawMetric

```GO
func (c *customMetricsClient) GetRawMetric(metricName string, namespace string, selector labels.Selector, metricSelector labels.Selector) (PodMetricsInfo, time.Time, error) {
	// 调用client.NamespacedMetrics(namespace).GetForObjects方法获取metrics和err
	metrics, err := c.client.NamespacedMetrics(namespace).GetForObjects(schema.GroupKind{Kind: "Pod"}, selector, metricName, metricSelector)
	if err != nil {
		// 如果获取metrics的过程出现错误，返回nil, time.Time{}, 以err为参数调用fmt.Errorf函数构造一个错误类型的值
		return nil, time.Time{}, fmt.Errorf("unable to fetch metrics from custom metrics API: %v", err)
	}

	// 如果metrics的Items字段长度为0，返回nil, time.Time{}，以自定义的错误信息为参数调用fmt.Errorf函数构造一个错误类型的值
	if len(metrics.Items) == 0 {
		return nil, time.Time{}, fmt.Errorf("no metrics returned from custom metrics API")
	}

	// 创建一个PodMetricsInfo类型的map，长度为metrics.Items的长度
	res := make(PodMetricsInfo, len(metrics.Items))
	// 遍历metrics.Items的每一个元素，使用_占位符忽略索引，m为metrics.Items的元素值
	for _, m := range metrics.Items {
		// 如果m.WindowSeconds不为nil，则将window初始化为time.Duration类型的*m.WindowSeconds * time.Second，否则window为metricServerDefaultMetricWindow
		window := metricServerDefaultMetricWindow
		if m.WindowSeconds != nil {
			window = time.Duration(*m.WindowSeconds) * time.Second
		}
		// 将PodMetric结构体赋值给res[m.DescribedObject.Name]，其中Timestamp字段为m.Timestamp.Time，Window字段为window，Value字段为m.Value.MilliValue()
		res[m.DescribedObject.Name] = PodMetric{
			Timestamp: m.Timestamp.Time,
			Window:    window,
			Value:     int64(m.Value.MilliValue()),
		}

		// 调用m.Value.MilliValue()，但并未使用其返回值
		m.Value.MilliValue()
	}

	// 将metrics.Items的第一个元素的Timestamp.Time赋值给timestamp
	timestamp := metrics.Items[0].Timestamp.Time

	// 返回res，timestamp和nil
	return res, timestamp, nil
}
```

#### GetObjectMetric

```GO
func (c *customMetricsClient) GetObjectMetric(metricName string, namespace string, objectRef *autoscaling.CrossVersionObjectReference, metricSelector labels.Selector) (int64, time.Time, error) {
	// 从对象引用中获得GroupVersionKind
	gvk := schema.FromAPIVersionAndKind(objectRef.APIVersion, objectRef.Kind)
	var metricValue *customapi.MetricValue
	var err error
	if gvk.Kind == "Namespace" && gvk.Group == "" {
		// 如果对象是命名空间，那么我们需要在根级别调用RootScopedMetrics()函数
		// NB: 我们在这里忽略命名空间名称，因为CrossVersionObjectReference不应允许您逃脱您的命名空间
		metricValue, err = c.client.RootScopedMetrics().GetForObject(gvk.GroupKind(), namespace, metricName, metricSelector)
	} else {
		// 否则，对象是在特定的命名空间中，我们将使用NamespacedMetrics()函数
		metricValue, err = c.client.NamespacedMetrics(namespace).GetForObject(gvk.GroupKind(), objectRef.Name, metricName, metricSelector)
	}

	if err != nil {
		// 如果获取MetricValue失败，则返回错误
		return 0, time.Time{}, fmt.Errorf("unable to fetch metrics from custom metrics API: %v", err)
	}

	// 否则，我们将返回MetricValue中的值和时间戳
	return metricValue.Value.MilliValue(), metricValue.Timestamp.Time, nil
}
```

### externalMetricsClient

```GO
type externalMetricsClient struct {
	client externalclient.ExternalMetricsClient
}
```

### GetExternalMetric

```GO
func (c *externalMetricsClient) GetExternalMetric(metricName, namespace string, selector labels.Selector) ([]int64, time.Time, error) {
    // 使用外部的metrics API获取指定名称的metrics
    metrics, err := c.client.NamespacedMetrics(namespace).List(metricName, selector)
    if err != nil {
        // 如果获取失败，返回一个空的[]int64切片，time.Time类型的零值，和一个包含错误信息的error
        return []int64{}, time.Time{}, fmt.Errorf("unable to fetch metrics from external metrics API: %v", err)
    }

    // 如果获取到的metrics为空，返回nil，time.Time类型的零值，和一个包含错误信息的error
    if len(metrics.Items) == 0 {
        return nil, time.Time{}, fmt.Errorf("no metrics returned from external metrics API")
    }

    // 如果获取到的metrics不为空，从中提取指标值并将其添加到一个切片中
    res := make([]int64, 0)
    for _, m := range metrics.Items {
        res = append(res, m.Value.MilliValue())
    }

    // 获取第一个指标的时间戳并返回结果切片，时间戳和一个nil的error
    timestamp := metrics.Items[0].Timestamp.Time
    return res, timestamp, nil
}
```

## ReplicaCalculator

- 计算目标 Pod 数量

```go
type ReplicaCalculator struct {
	metricsClient                 metricsclient.MetricsClient
	podLister                     corelisters.PodLister
    // 指定容器指标值的允许波动范围，通常为 0.1
	tolerance                     float64
    // 指定在容器指标数据不足时计算 CPU 使用率的时间窗口，通常为 2 分钟
	cpuInitializationPeriod       time.Duration
    // 在启动 Pod 时等待一段时间以获取其就绪状态的延迟时间 通常为 10 秒
	delayOfInitialReadinessStatus time.Duration
}
```

### New

```go
func NewReplicaCalculator(metricsClient metricsclient.MetricsClient, podLister corelisters.PodLister, tolerance float64, cpuInitializationPeriod, delayOfInitialReadinessStatus time.Duration) *ReplicaCalculator {
	return &ReplicaCalculator{
		metricsClient:                 metricsClient,
		podLister:                     podLister,
		tolerance:                     tolerance,
		cpuInitializationPeriod:       cpuInitializationPeriod,
		delayOfInitialReadinessStatus: delayOfInitialReadinessStatus,
	}
}
```

### GetResourceReplicas

- 根据目标利用率、资源指标、namespace和选择器等参数计算资源的副本数和利用率

```go
func (c *ReplicaCalculator) GetResourceReplicas(ctx context.Context, currentReplicas int32, targetUtilization int32, resource v1.ResourceName, namespace string, selector labels.Selector, container string) (replicaCount int32, utilization int32, rawUtilization int64, timestamp time.Time, err error) {
    // 获取资源的指标和时间戳
	metrics, timestamp, err := c.metricsClient.GetResourceMetric(ctx, resource, namespace, selector, container)
	if err != nil {
		return 0, 0, 0, time.Time{}, fmt.Errorf("unable to get metrics for resource %s: %v", resource, err)
	}
    // 获取pod列表
	podList, err := c.podLister.Pods(namespace).List(selector)
	if err != nil {
		return 0, 0, 0, time.Time{}, fmt.Errorf("unable to get pods while calculating replica count: %v", err)
	}
    // 如果pod列表为空，则返回错误
	if len(podList) == 0 {
		return 0, 0, 0, time.Time{}, fmt.Errorf("no pods returned by selector while calculating replica count")
	}
	// groupPods函数将pod分为已准备好的pod、未准备好的pod、缺失的pod和忽略的pod四种情况，并返回各种pod的数量
	readyPodCount, unreadyPods, missingPods, ignoredPods := groupPods(podList, metrics, resource, c.cpuInitializationPeriod, c.delayOfInitialReadinessStatus)
    // 移除忽略的pod和未准备好的pod的指标
	removeMetricsForPods(metrics, ignoredPods)
	removeMetricsForPods(metrics, unreadyPods)
    // 如果metrics为空，则返回错误
	if len(metrics) == 0 {
		return 0, 0, 0, time.Time{}, fmt.Errorf("did not receive metrics for targeted pods (pods might be unready)")
	}
	// calculatePodRequests函数计算pod的请求资源
	requests, err := calculatePodRequests(podList, container, resource)
	if err != nil {
		return 0, 0, 0, time.Time{}, err
	}
    // GetResourceUtilizationRatio函数计算资源的使用率比率、利用率和原始利用率
	usageRatio, utilization, rawUtilization, err := metricsclient.GetResourceUtilizationRatio(metrics, requests, targetUtilization)
	if err != nil {
		return 0, 0, 0, time.Time{}, err
	}
	// 如果存在未准备好的pod且使用率比率大于1，则进行扩容
	scaleUpWithUnready := len(unreadyPods) > 0 && usageRatio > 1.0
	if !scaleUpWithUnready && len(missingPods) == 0 {
		if math.Abs(1.0-usageRatio) <= c.tolerance {
			// 如果变化太小，则返回当前副本数
			return currentReplicas, utilization, rawUtilization, timestamp, nil
		}

		// 如果不存在未准备好的pod和缺失的pod，则现在可以计算新的副本数
		return int32(math.Ceil(usageRatio * float64(readyPodCount))), utilization, rawUtilization, timestamp, nil
	}

	if len(missingPods) > 0 {
		if usageRatio < 1.0 {
			// 在缩小规模时，将缺失的 Pod 视为使用其资源请求的 100%（全部）
			// 或对于大于 100% 的目标利用率，视为使用目标利用率
			fallbackUtilization := int64(max(100, targetUtilization))
			for podName := range missingPods {
				metrics[podName] = metricsclient.PodMetric{Value: requests[podName] * fallbackUtilization / 100}
			}
		} else if usageRatio > 1.0 {
			// 在扩容时，把缺失的 pod 视为使用 0% 的资源请求
			for podName := range missingPods {
				metrics[podName] = metricsclient.PodMetric{Value: 0}
			}
		}
	}

	if scaleUpWithUnready {
		// 在扩容时，把未就绪的 pod 视为使用 0% 的资源请求
		for podName := range unreadyPods {
			metrics[podName] = metricsclient.PodMetric{Value: 0}
		}
	}

	// 重新使用新的指标值运行利用率计算
	newUsageRatio, _, _, err := metricsclient.GetResourceUtilizationRatio(metrics, requests, targetUtilization)
	if err != nil {
		return 0, utilization, rawUtilization, time.Time{}, err
	}
	// 如果新的利用率变化量很小，或者新的利用率会导致扩缩容方向的改变，就返回当前的副本数和利用率
	if math.Abs(1.0-newUsageRatio) <= c.tolerance || (usageRatio < 1.0 && newUsageRatio > 1.0) || (usageRatio > 1.0 && newUsageRatio < 1.0) {
		// 如果改变太小，或新的利用率会导致扩缩容方向的改变，返回当前的副本数和利用率
		return currentReplicas, utilization, rawUtilization, timestamp, nil
	}
	// 计算新的副本数
	newReplicas := int32(math.Ceil(newUsageRatio * float64(len(metrics))))
    // 如果新的利用率导致扩缩容方向改变，就返回当前的副本数和利用率
	if (newUsageRatio < 1.0 && newReplicas > currentReplicas) || (newUsageRatio > 1.0 && newReplicas < currentReplicas) {
		// 如果新的利用率导致扩缩容方向改变，返回当前的副本数和利用率
		return currentReplicas, utilization, rawUtilization, timestamp, nil
	}

	// 返回计算所得的结果，其中考虑了计算中使用的副本数
	return newReplicas, utilization, rawUtilization, timestamp, nil
}
```

#### groupPods

```GO
// groupPods 用于按照指定条件对 Pod 列表进行分类
// 参数:
//    - pods：Pod 列表
//    - metrics: Metrics 容器，用于存储 Pod 的指标信息
//    - resource: 资源名，目前只支持 CPU
//    - cpuInitializationPeriod: 初始时间期间（Duration），CPU 指标计算中使用
//    - delayOfInitialReadinessStatus: 初始状态延迟（Duration），CPU 指标计算中使用
// 返回值:
//    - readyPodCount: 已就绪 Pod 数量
//    - unreadyPods: 未就绪 Pod 集合
//    - missingPods: 没有指标的 Pod 集合
//    - ignoredPods: 忽略的 Pod 集合（已删除或状态为 PodFailed）
func groupPods(pods []*v1.Pod, metrics metricsclient.PodMetricsInfo, resource v1.ResourceName, cpuInitializationPeriod, delayOfInitialReadinessStatus time.Duration) (readyPodCount int, unreadyPods, missingPods, ignoredPods sets.String) {
    missingPods = sets.NewString()  // 创建新的缺少指标的 Pod 集合
    unreadyPods = sets.NewString()  // 创建新的未就绪 Pod 集合
    ignoredPods = sets.NewString()  // 创建新的忽略的 Pod 集合
    for _, pod := range pods {  // 遍历 Pod 列表
        // 如果 Pod 已经被删除或状态为 PodFailed，则将其加入忽略的 Pod 集合并跳过
        if pod.DeletionTimestamp != nil || pod.Status.Phase == v1.PodFailed {
            ignoredPods.Insert(pod.Name)
            continue
        }
        // 如果 Pod 的状态为 Pending，则将其加入未就绪 Pod 集合并跳过
        if pod.Status.Phase == v1.PodPending {
            unreadyPods.Insert(pod.Name)
            continue
        }
        // 如果该 Pod 没有对应的 Metrics，将其加入缺少指标的 Pod 集合并跳过
        metric, found := metrics[pod.Name]
        if !found {
            missingPods.Insert(pod.Name)
            continue
        }
        // 如果该 Pod 未就绪，则将其加入未就绪 Pod 集合并跳过
        if resource == v1.ResourceCPU {
            var unready bool
            _, condition := podutil.GetPodCondition(&pod.Status, v1.PodReady)
            if condition == nil || pod.Status.StartTime == nil {
                unready = true
            } else {
                // 如果 Pod 仍处于可能的初始化期间，则不将其加入任何 Pod 集合
                if pod.Status.StartTime.Add(cpuInitializationPeriod).After(time.Now()) {
                    // 如果 Pod 未就绪或上一个状态转换后的时间窗口没有收集到指标，则将其加入未就绪 Pod 集合
                    unready = condition.Status == v1.ConditionFalse || metric.Timestamp.Before(condition.LastTransitionTime.Time.Add(metric.Window))
                } else {
                    // 如果 Pod 未就绪 则忽略度量
                    unready = condition.Status == v1.ConditionFalse && pod.Status.StartTime.Add(delayOfInitialReadinessStatus).After(condition.LastTransitionTime.Time)
				}
			}
			if unready {
				unreadyPods.Insert(pod.Name)
				continue
			}
		}
		readyPodCount++
	}
	return
}
```

#### removeMetricsForPods

```GO
func removeMetricsForPods(metrics metricsclient.PodMetricsInfo, pods sets.String) {
	for _, pod := range pods.UnsortedList() {
		delete(metrics, pod)
	}
}
```

#### calculatePodRequests

```GO
func calculatePodRequests(pods []*v1.Pod, container string, resource v1.ResourceName) (map[string]int64, error) {
    // 声明一个 map 类型的变量 requests，用于存储 Pod 的资源请求总量
	requests := make(map[string]int64, len(pods))
	// 遍历 pods 切片，对每个 Pod 执行以下操作
    for _, pod := range pods {
        // 初始化变量 podSum 为 0
        podSum := int64(0)

        // 遍历 Pod 中的容器，对每个容器执行以下操作
        for _, c := range pod.Spec.Containers {
            // 如果 container 为空或者容器名与 container 相同
            if container == "" || container == c.Name {
                // 检查该容器的资源请求中是否有 resource 这个资源名
                if containerRequest, ok := c.Resources.Requests[resource]; ok {
                    // 如果有，将容器的资源请求值转换为毫秒，然后加到 podSum 变量上
                    podSum += containerRequest.MilliValue()
                } else {
                    // 如果没有，返回一个错误，说明容器中缺少指定的资源请求
                    return nil, fmt.Errorf("missing request for %s in container %s of Pod %s", resource, c.Name, pod.ObjectMeta.Name)
                }
            }
        }
        // 将 Pod 的名称映射到资源请求总量
        requests[pod.Name] = podSum
    }
    // 返回 requests 映射和一个空的错误对象，表示函数执行成功
    return requests, nil
}
```

#### GetResourceUtilizationRatio

```GO
func GetResourceUtilizationRatio(metrics PodMetricsInfo, requests map[string]int64, targetUtilization int32) (utilizationRatio float64, currentUtilization int32, rawAverageValue int64, err error) {
	metricsTotal := int64(0)
	requestsTotal := int64(0)
	numEntries := 0

	// 遍历 metrics 映射，对每个 Pod 执行以下操作
    for podName, metric := range metrics {
        // 从 requests 映射中获取该 Pod 的资源请求总量
        request, hasRequest := requests[podName]
        // 如果 requests 映射中不存在该 Pod 的资源请求，则跳过该 Pod
        if !hasRequest {
            // 由于已经在其他地方检查了缺少请求的情况，所以我们认为缺少请求等同于冗余指标
            continue
        }
        // 计算 metricsTotal 和 requestsTotal，分别为所有 Pod 的指标值和请求总量之和
        metricsTotal += metric.Value
        requestsTotal += request
        numEntries++
    }

    // 如果请求的集合与指标集合完全不相交，则可能存在请求总量为零的问题
    if requestsTotal == 0 {
        return 0, 0, 0, fmt.Errorf("no metrics returned matched known pods")
    }

    // 计算当前利用率，并将其存储在 currentUtilization 变量中
    currentUtilization = int32((metricsTotal * 100) / requestsTotal)

    // 返回当前利用率与目标利用率的比率，当前利用率，每个 Pod 的平均资源利用率，以及一个空的错误对象，表示函数执行成功
    return float64(currentUtilization) / float64(targetUtilization), currentUtilization, metricsTotal / int64(numEntries), nil
}
```

### GetRawResourceReplicas

```GO
func (c *ReplicaCalculator) GetRawResourceReplicas(ctx context.Context, currentReplicas int32, targetUsage int64, resource v1.ResourceName, namespace string, selector labels.Selector, container string) (replicaCount int32, usage int64, timestamp time.Time, err error) {
	// 调用metricsClient结构体中的GetResourceMetric方法获取metrics、timestamp、err三个值
    metrics, timestamp, err := c.metricsClient.GetResourceMetric(ctx, resource, namespace, selector, container)

    // 如果有错误发生，返回错误信息
    if err != nil {
        return 0, 0, time.Time{}, fmt.Errorf("unable to get metrics for resource %s: %v", resource, err)
    }

    // 调用calcPlainMetricReplicas方法计算replicaCount、usage、err三个值
    replicaCount, usage, err = c.calcPlainMetricReplicas(metrics, currentReplicas, targetUsage, namespace, selector, resource)

    // 返回replicaCount、usage、timestamp、err四个值
    return replicaCount, usage, timestamp, err
}
```

#### calcPlainMetricReplicas

```go
func (c *ReplicaCalculator) calcPlainMetricReplicas(metrics metricsclient.PodMetricsInfo, currentReplicas int32, targetUsage int64, namespace string, selector labels.Selector, resource v1.ResourceName) (replicaCount int32, usage int64, err error) {

	// 通过 selector 和 namespace 获取 Pod 列表
	podList, err := c.podLister.Pods(namespace).List(selector)
	if err != nil {
		// 获取 Pod 列表失败
		return 0, 0, fmt.Errorf("unable to get pods while calculating replica count: %v", err)
	}

	if len(podList) == 0 {
		// Pod 列表为空
		return 0, 0, fmt.Errorf("no pods returned by selector while calculating replica count")
	}

	// 对 Pod 进行分类
	// readyPodCount 表示已经 ready 的 Pod 数量
	// unreadyPods 表示未 ready 的 Pod 数量
	// missingPods 表示不包含在 metrics 中的 Pod 数量
	// ignoredPods 表示被忽略的 Pod 数量
	readyPodCount, unreadyPods, missingPods, ignoredPods := groupPods(podList, metrics, resource, c.cpuInitializationPeriod, c.delayOfInitialReadinessStatus)
	// 从 metrics 中删除忽略和未 ready 的 Pod
	removeMetricsForPods(metrics, ignoredPods)
	removeMetricsForPods(metrics, unreadyPods)

	if len(metrics) == 0 {
		// 没有 Pod 的指标信息
		return 0, 0, fmt.Errorf("did not receive metrics for targeted pods (pods might be unready)")
	}

	// 获取 Pod 的利用率及总共的使用量
	usageRatio, usage := metricsclient.GetMetricUsageRatio(metrics, targetUsage)

	// 判断是否需要考虑未 ready 的 Pod
	scaleUpWithUnready := len(unreadyPods) > 0 && usageRatio > 1.0

	if !scaleUpWithUnready && len(missingPods) == 0 {
		if math.Abs(1.0-usageRatio) <= c.tolerance {
			// 如果变化的比例小于容差，则返回当前副本数
			return currentReplicas, usage, nil
		}

		// 如果不存在未 ready 或缺少的 Pod，则现在可以计算新的副本数
		return int32(math.Ceil(usageRatio * float64(readyPodCount))), usage, nil
	}

	if len(missingPods) > 0 {
		if usageRatio < 1.0 {
			// 在缩容时，将缺少的 Pod 视为使用目标数量
			for podName := range missingPods {
				metrics[podName] = metricsclient.PodMetric{Value: targetUsage}
			}
		} else {
			// 在扩容时，将缺少的 Pod 视为使用资源请求量的 0%
			for podName := range missingPods {
				metrics[podName] = metricsclient.PodMetric{Value: 0}
			}
		}
	}

	if scaleUpWithUnready {
		// 在扩容时，将未 ready 的 Pod 视为使用资源请求量的 0%
		for podName := range unreadyPods {
				metrics[podName] = metricsclient.PodMetric{Value: 0}
			}
		}
	}

	if scaleUpWithUnready {
		// 在扩容时，将未准备好的 pod 视为使用 0% 的资源请求
		for podName := range unreadyPods {
			metrics[podName] = metricsclient.PodMetric{Value: 0}
		}
	}

	// 使用新的值重新计算使用率
	newUsageRatio, _ := metricsclient.GetMetricUsageRatio(metrics, targetUsage)

	if math.Abs(1.0-newUsageRatio) <= c.tolerance || (usageRatio < 1.0 && newUsageRatio > 1.0) || (usageRatio > 1.0 && newUsageRatio < 1.0) {
		// 如果更改太小，或新的使用率会导致扩容方向的更改，则返回当前副本
		return currentReplicas, usage, nil
	}
	// 计算新的副本数
	newReplicas := int32(math.Ceil(newUsageRatio * float64(len(metrics))))
	if (newUsageRatio < 1.0 && newReplicas > currentReplicas) || (newUsageRatio > 1.0 && newReplicas < currentReplicas) {
		// 如果度量长度的更改会导致扩容方向的更改，则返回当前副本
		return currentReplicas, usage, nil
	}

	// 返回计算出的副本数，使用率及错误信息
	// 所考虑的副本数是我们的计算所涉及的副本数
	return newReplicas, usage, nil
}
```

##### GetMetricUsageRatio

```go
func GetMetricUsageRatio(metrics PodMetricsInfo, targetUsage int64) (usageRatio float64, currentUsage int64) {
	metricsTotal := int64(0)
    // 对于每个度量值计算总和
	for _, metric := range metrics {
		metricsTotal += metric.Value
	}
	// 计算当前使用量
	currentUsage = metricsTotal / int64(len(metrics))
	// 返回使用率比率和当前使用量
	return float64(currentUsage) / float64(targetUsage), currentUsage
}
```

### GetMetricReplicas

```go
func (c *ReplicaCalculator) GetMetricReplicas(currentReplicas int32, targetUsage int64, metricName string, namespace string, selector labels.Selector, metricSelector labels.Selector) (replicaCount int32, usage int64, timestamp time.Time, err error) {
    // 获取原始的指标数据
	metrics, timestamp, err := c.metricsClient.GetRawMetric(metricName, namespace, selector, metricSelector)
	if err != nil {
        // 获取指标数据出错时，返回错误信息
		return 0, 0, time.Time{}, fmt.Errorf("unable to get metric %s: %v", metricName, err)
	}
	// 根据原始指标数据计算Pod数量和使用情况
	replicaCount, usage, err = c.calcPlainMetricReplicas(metrics, currentReplicas, targetUsage, namespace, selector, v1.ResourceName(""))
	return replicaCount, usage, timestamp, err
}
```

### GetObjectMetricReplicas

```go
func (c *ReplicaCalculator) GetObjectMetricReplicas(currentReplicas int32, targetUsage int64, metricName string, namespace string, objectRef *autoscaling.CrossVersionObjectReference, selector labels.Selector, metricSelector labels.Selector) (replicaCount int32, usage int64, timestamp time.Time, err error) {
    // 使用指定的 metricName、namespace、objectRef 和 metricSelector 等参数获取对象指标的使用量。
	usage, _, err = c.metricsClient.GetObjectMetric(metricName, namespace, objectRef, metricSelector)
	if err != nil {
        // 如果出错，返回错误信息。
		return 0, 0, time.Time{}, fmt.Errorf("unable to get metric %s: %v on %s %s/%s", metricName, objectRef.Kind, namespace, objectRef.Name, err)
	}
	// 计算对象指标的使用率。
	usageRatio := float64(usage) / float64(targetUsage)
    // 使用当前的使用率和其他参数计算对象指标的副本数量，返回值为 replicaCount、timestamp 和 err。
	replicaCount, timestamp, err = c.getUsageRatioReplicaCount(currentReplicas, usageRatio, namespace, selector)
	return replicaCount, usage, timestamp, err
}
```

#### getUsageRatioReplicaCount

```go
func (c *ReplicaCalculator) getUsageRatioReplicaCount(currentReplicas int32, usageRatio float64, namespace string, selector labels.Selector) (replicaCount int32, timestamp time.Time, err error) {
    // 如果当前的副本数量不为 0
    if currentReplicas != 0 {
        // 如果变化太小，就返回当前的副本数量
        if math.Abs(1.0-usageRatio) <= c.tolerance {
            return currentReplicas, timestamp, nil
        }
        // 获取已经就绪的 Pod 数量
        readyPodCount := int64(0)
        readyPodCount, err = c.getReadyPodsCount(namespace, selector)
        if err != nil {
            return 0, time.Time{}, fmt.Errorf("unable to calculate ready pods: %s", err)
        }
        // 根据 usageRatio 和已就绪 Pod 数量计算新的副本数量
        replicaCount = int32(math.Ceil(usageRatio * float64(readyPodCount)))
    } else {
        // 如果当前的副本数量为 0，则根据 usageRatio 决定是缩容到 0 还是扩容到 n 个 Pod
        replicaCount = int32(math.Ceil(usageRatio))
    }

    return replicaCount, timestamp, err
}
```

#### getReadyPodsCount

```go
func (c *ReplicaCalculator) getReadyPodsCount(namespace string, selector labels.Selector) (int64, error) {
    // 根据选择器获取 Namespace 中匹配的 Pod 列表
    podList, err := c.podLister.Pods(namespace).List(selector)
    if err != nil {
        return 0, fmt.Errorf("unable to get pods while calculating replica count: %v", err)
    }

    // 如果 Pod 列表为空，则返回错误
    if len(podList) == 0 {
        return 0, fmt.Errorf("no pods returned by selector while calculating replica count")
    }

    readyPodCount := 0
    // 遍历 Pod 列表，计算准备好的 Pod 数量
    for _, pod := range podList {
        if pod.Status.Phase == v1.PodRunning && podutil.IsPodReady(pod) {
            readyPodCount++
        }
    }
    return int64(readyPodCount), nil
}
```

### GetObjectPerPodMetricReplicas

```go
func (c *ReplicaCalculator) GetObjectPerPodMetricReplicas(statusReplicas int32, targetAverageUsage int64, metricName string, namespace string, objectRef *autoscaling.CrossVersionObjectReference, metricSelector labels.Selector) (replicaCount int32, usage int64, timestamp time.Time, err error) {
    // 获取指定对象在指定 Namespace 中的指定指标的使用情况和时间戳
    usage, timestamp, err = c.metricsClient.GetObjectMetric(metricName, namespace, objectRef, metricSelector)
    if err != nil {
        return 0, 0, time.Time{}, fmt.Errorf("unable to get metric %s: %v on %s %s/%s", metricName, objectRef.Kind, namespace, objectRef.Name, err)
    }

    // 初始的副本数量为目前的副本数量
    replicaCount = statusReplicas

    // 计算当前使用率与目标使用率的比率
    usageRatio := float64(usage) / (float64(targetAverageUsage) * float64(replicaCount))
    // 如果变化太小，则不修改副本数量
    if math.Abs(1.0-usageRatio) > c.tolerance {
        // 否则根据使用率和目标使用率计算新的副本数量
        replicaCount = int32(math.Ceil(float64(usage) / float64(targetAverageUsage)))
    }
    // 计算每个 Pod 的使用量
    usage = int64(math.Ceil(float64(usage) / float64(statusReplicas)))
    return replicaCount, usage, timestamp, nil
}
```

### GetExternalMetricReplicas

```go
func (c *ReplicaCalculator) GetExternalMetricReplicas(currentReplicas int32, targetUsage int64, metricName, namespace string, metricSelector *metav1.LabelSelector, podSelector labels.Selector) (replicaCount int32, usage int64, timestamp time.Time, err error) {
    // 将 metav1.LabelSelector 转换为 labels.Selector
    metricLabelSelector, err := metav1.LabelSelectorAsSelector(metricSelector)
    if err != nil {
        return 0, 0, time.Time{}, err
    }

    // 获取外部指标的值
    metrics, _, err := c.metricsClient.GetExternalMetric(metricName, namespace, metricLabelSelector)
    if err != nil {
        return 0, 0, time.Time{}, fmt.Errorf("unable to get external metric %s/%s/%+v: %s", namespace, metricName, metricSelector, err)
    }

    // 计算使用率
    usage = 0
    for _, val := range metrics {
        usage = usage + val
    }
    usageRatio := float64(usage) / float64(targetUsage)

    // 根据使用率计算所需的副本数
    replicaCount, timestamp, err = c.getUsageRatioReplicaCount(currentReplicas, usageRatio, namespace, podSelector)
    return replicaCount, usage, timestamp, err
}

```

### GetExternalPerPodMetricReplicas

```go
func (c *ReplicaCalculator) GetExternalPerPodMetricReplicas(statusReplicas int32, targetUsagePerPod int64, metricName, namespace string, metricSelector *metav1.LabelSelector) (replicaCount int32, usage int64, timestamp time.Time, err error) {
    // 转换metricSelector标签选择器为selector
	metricLabelSelector, err := metav1.LabelSelectorAsSelector(metricSelector)
	if err != nil {
		return 0, 0, time.Time{}, err
	}
    // 从c.metricsClient中获取外部度量信息，使用metricName，namespace和metricSelector过滤结果
	// 获取到的度量值保存在metrics变量中，时间戳保存在timestamp中
	metrics, timestamp, err := c.metricsClient.GetExternalMetric(metricName, namespace, metricLabelSelector)
	if err != nil {
		return 0, 0, time.Time{}, fmt.Errorf("unable to get external metric %s/%s/%+v: %s", namespace, metricName, metricSelector, err)
	}
	usage = 0
    // 计算度量值的总和
	for _, val := range metrics {
		usage = usage + val
	}

	// 复制statusReplicas值到replicaCount变量
    replicaCount = statusReplicas
    // 计算当前用量与目标用量之比，使用float64类型的usageRatio变量保存
    usageRatio := float64(usage) / (float64(targetUsagePerPod) * float64(replicaCount))
    // 如果用量比例变化大于tolerance，则更新replicaCount
    if math.Abs(1.0-usageRatio) > c.tolerance {
        // 更新replicaCount以使用量符合目标用量
        replicaCount = int32(math.Ceil(float64(usage) / float64(targetUsagePerPod)))
    }
    // 计算平均用量并将其存储在usage变量中
    usage = int64(math.Ceil(float64(usage) / float64(statusReplicas)))
    return replicaCount, usage, timestamp, nil
}
```

## Monitor

```GO
type Monitor interface {
    // 监视并报告控制器的协调操作（reconciliation operation）的结果，记录操作类型（例如ScaleUp、ScaleDown、Check等）、
    // 错误类型（例如NoScale、ScaleFailed、FetchFailed等）和操作持续时间（duration）。
	ObserveReconciliationResult(action ActionLabel, err ErrorLabel, duration time.Duration)
    // 监视并报告度量计算的结果，记录计算类型（例如GetExternalMetric、GetResourceMetric等）、
    // 错误类型（例如GetMetricFailed、ParseMetricFailed等）、计算持续时间（duration）和度量源类型（metricType）。
	ObserveMetricComputationResult(action ActionLabel, err ErrorLabel, duration time.Duration, metricType v2.MetricSourceType)
}
```

```GO
// 控制器执行的操作类型
type ActionLabel string
// 控制器的错误类型
type ErrorLabel string

const (
	ActionLabelScaleUp   ActionLabel = "scale_up"
	ActionLabelScaleDown ActionLabel = "scale_down"
	ActionLabelNone      ActionLabel = "none"

	// 表示由于HPA对象的无效规范而产生的错误类型
	ErrorLabelSpec ErrorLabel = "spec"
	// 表示由于内部计算或与其他组件通信而产生的错误类型
	ErrorLabelInternal ErrorLabel = "internal"
    // 表示节点错误类型
	ErrorLabelNone     ErrorLabel = "none"
)
```

### 实现

```go
type monitor struct{}

func New() Monitor {
	return &monitor{}
}

func (r *monitor) ObserveReconciliationResult(action ActionLabel, err ErrorLabel, duration time.Duration) {
	reconciliationsTotal.WithLabelValues(string(action), string(err)).Inc()
	reconciliationsDuration.WithLabelValues(string(action), string(err)).Observe(duration.Seconds())
}

func (r *monitor) ObserveMetricComputationResult(action ActionLabel, err ErrorLabel, duration time.Duration, metricType v2.MetricSourceType) {
	metricComputationTotal.WithLabelValues(string(action), string(err), string(metricType)).Inc()
	metricComputationDuration.WithLabelValues(string(action), string(err), string(metricType)).Observe(duration.Seconds())
}
```

### metrics

```GO

const (
	// hpaControllerSubsystem - subsystem name used by HPA controller
	hpaControllerSubsystem = "horizontal_pod_autoscaler_controller"
)

var (
	reconciliationsTotal = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Subsystem:      hpaControllerSubsystem,
			Name:           "reconciliations_total",
			Help:           "Number of reconciliations of HPA controller. The label 'action' should be either 'scale_down', 'scale_up', or 'none'. Also, the label 'error' should be either 'spec', 'internal', or 'none'. Note that if both spec and internal errors happen during a reconciliation, the first one to occur is reported in `error` label.",
			StabilityLevel: metrics.ALPHA,
		}, []string{"action", "error"})

	reconciliationsDuration = metrics.NewHistogramVec(
		&metrics.HistogramOpts{
			Subsystem:      hpaControllerSubsystem,
			Name:           "reconciliation_duration_seconds",
			Help:           "The time(seconds) that the HPA controller takes to reconcile once. The label 'action' should be either 'scale_down', 'scale_up', or 'none'. Also, the label 'error' should be either 'spec', 'internal', or 'none'. Note that if both spec and internal errors happen during a reconciliation, the first one to occur is reported in `error` label.",
			Buckets:        metrics.ExponentialBuckets(0.001, 2, 15),
			StabilityLevel: metrics.ALPHA,
		}, []string{"action", "error"})
	metricComputationTotal = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Subsystem:      hpaControllerSubsystem,
			Name:           "metric_computation_total",
			Help:           "Number of metric computations. The label 'action' should be either 'scale_down', 'scale_up', or 'none'. Also, the label 'error' should be either 'spec', 'internal', or 'none'. The label 'metric_type' corresponds to HPA.spec.metrics[*].type",
			StabilityLevel: metrics.ALPHA,
		}, []string{"action", "error", "metric_type"})
	metricComputationDuration = metrics.NewHistogramVec(
		&metrics.HistogramOpts{
			Subsystem:      hpaControllerSubsystem,
			Name:           "metric_computation_duration_seconds",
			Help:           "The time(seconds) that the HPA controller takes to calculate one metric. The label 'action' should be either 'scale_down', 'scale_up', or 'none'. The label 'error' should be either 'spec', 'internal', or 'none'. The label 'metric_type' corresponds to HPA.spec.metrics[*].type",
			Buckets:        metrics.ExponentialBuckets(0.001, 2, 15),
			StabilityLevel: metrics.ALPHA,
		}, []string{"action", "error", "metric_type"})

	metricsList = []metrics.Registerable{
		reconciliationsTotal,
		reconciliationsDuration,
		metricComputationTotal,
		metricComputationDuration,
	}
)

var register sync.Once

// Register all metrics.
func Register() {
	// Register the metrics.
	register.Do(func() {
		registerMetrics(metricsList...)
	})
}

// RegisterMetrics registers a list of metrics.
func registerMetrics(extraMetrics ...metrics.Registerable) {
	for _, metric := range extraMetrics {
		legacyregistry.MustRegister(metric)
	}
}
```

