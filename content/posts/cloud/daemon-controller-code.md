---
title: Daemon Controller Code
subtitle:
date: 2023-03-27T20:34:12+08:00
draft: false
toc: true
categories: 
  - cloud
tags: 
  - kubernetes
  - controller
authors:
    - haiyux
# featuredImagePreview: /img/preview/controller/deployment-controller.jpg
---

## 简介

Kubernetes 中的 DaemonSet 是一种控制器，用于确保在集群中的每个节点上运行一个副本（Pod）的特定应用程序。 它被称为 DaemonSet，因为它在每个节点上“守护”着该应用程序的一个实例。

DaemonSet 控制器是一个自主的 K8s API 对象，其作用是在每个节点上自动创建和维护一个 Pod 的副本。它非常适合那些需要在每个节点上运行的应用程序，如日志收集器、监控代理或其他后台进程。

当一个新节点加入集群时，DaemonSet 会自动创建一个新的 Pod 实例。反之，当节点从集群中删除时，DaemonSet 会自动将对应的 Pod 实例删除。这样，DaemonSet 可以确保集群中每个节点都有一个实例在运行，并且可以自动管理实例的数量。

除了基本的 Pod 调度和维护功能外，DaemonSet 还提供了一些其他的特性，例如能够通过设置标签选择器，从而只在特定节点上启动 Pod 实例。还可以使用容忍性设置，从而在特定的节点上禁用 DaemonSet。

## 结构体

```go
type DaemonSetsController struct {
	kubeClient clientset.Interface
	// 用于记录 DaemonSet 控制器的事件，包括创建、更新和删除等操作
	eventBroadcaster record.EventBroadcaster
	eventRecorder    record.EventRecorder
	
    // 创建、更新和删除 Pod 和 ControllerRevision 对象的控制器接口
	podControl controller.PodControlInterface
	crControl  controller.ControllerRevisionControlInterface

	// 表示在创建或删除一定数量的副本之后，控制器会暂时挂起操作，直到观察到一定数量的 Watch 事件后才会恢复正常操作
	burstReplicas int

	// 同步 DaemonSet 对象
	syncHandler func(ctx context.Context, dsKey string) error
	// 添加到队列
	enqueueDaemonSet func(ds *apps.DaemonSet)
	// 用于跟踪控制器期望看到的 Pod 创建和删除事件，以确保控制器和实际状态之间的一致性
    // https://haiyux.cc/2023/03/20/replicaset-controller-code/#controllerexpectationsinterface
	expectations controller.ControllerExpectationsInterface
    
	dsLister appslisters.DaemonSetLister
	dsStoreSynced cache.InformerSynced
	
	historyLister appslisters.ControllerRevisionLister
	historyStoreSynced cache.InformerSynced

	podLister corelisters.PodLister
	podStoreSynced cache.InformerSynced

	nodeLister corelisters.NodeLister
	nodeStoreSynced cache.InformerSynced

	// 工作队列
	queue workqueue.RateLimitingInterface
	// 用于在处理失败的 Pod 时进行退避重试的机制
	failedPodsBackoff *flowcontrol.Backoff
}
```

## New

```go
func NewDaemonSetsController(
	ctx context.Context,
	daemonSetInformer appsinformers.DaemonSetInformer,
	historyInformer appsinformers.ControllerRevisionInformer,
	podInformer coreinformers.PodInformer,
	nodeInformer coreinformers.NodeInformer,
	kubeClient clientset.Interface,
	failedPodsBackoff *flowcontrol.Backoff,
) (*DaemonSetsController, error) {
	eventBroadcaster := record.NewBroadcaster()
	logger := klog.FromContext(ctx)
	dsc := &DaemonSetsController{
		kubeClient:       kubeClient,
		eventBroadcaster: eventBroadcaster,
		eventRecorder:    eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "daemonset-controller"}),
		podControl: controller.RealPodControl{
			KubeClient: kubeClient,
			Recorder:   eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "daemonset-controller"}),
		},
		crControl: controller.RealControllerRevisionControl{
			KubeClient: kubeClient,
		},
		burstReplicas: BurstReplicas,
		expectations:  controller.NewControllerExpectations(),
		queue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "daemonset"),
	}
	// 监控daemonset
	daemonSetInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			dsc.addDaemonset(logger, obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			dsc.updateDaemonset(logger, oldObj, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			dsc.deleteDaemonset(logger, obj)
		},
	})
	dsc.dsLister = daemonSetInformer.Lister()
	dsc.dsStoreSynced = daemonSetInformer.Informer().HasSynced
	
    // 监控history
	historyInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			dsc.addHistory(logger, obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			dsc.updateHistory(logger, oldObj, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			dsc.deleteHistory(logger, obj)
		},
	})
	dsc.historyLister = historyInformer.Lister()
	dsc.historyStoreSynced = historyInformer.Informer().HasSynced

	// 监控pod
	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			dsc.addPod(logger, obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			dsc.updatePod(logger, oldObj, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			dsc.deletePod(logger, obj)
		},
	})
	dsc.podLister = podInformer.Lister()
	dsc.podStoreSynced = podInformer.Informer().HasSynced
	
    // 监控node的add 和 update
	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			dsc.addNode(logger, obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			dsc.updateNode(logger, oldObj, newObj)
		},
	},
	)
	dsc.nodeStoreSynced = nodeInformer.Informer().HasSynced
	dsc.nodeLister = nodeInformer.Lister()

	dsc.syncHandler = dsc.syncDaemonSet
	dsc.enqueueDaemonSet = dsc.enqueue
	
    // 设置处理失败的 Pod 时进行退避重试的机制
	dsc.failedPodsBackoff = failedPodsBackoff

	return dsc, nil
}
```

### enqueueDaemonSet

```go
func (dsc *DaemonSetsController) enqueue(ds *apps.DaemonSet) {
	key, err := controller.KeyFunc(ds)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %#v: %v", ds, err))
		return
	}

	// TODO: Handle overlapping controllers better. See comment in ReplicationManager.
	dsc.queue.Add(key)
}
```

### 队列相关

#### deamonset

```GO
func (dsc *DaemonSetsController) addDaemonset(logger klog.Logger, obj interface{}) {
	ds := obj.(*apps.DaemonSet)
	logger.V(4).Info("Adding daemon set", "daemonset", klog.KObj(ds))
	dsc.enqueueDaemonSet(ds)
}

func (dsc *DaemonSetsController) updateDaemonset(logger klog.Logger, cur, old interface{}) {
	oldDS := old.(*apps.DaemonSet)
	curDS := cur.(*apps.DaemonSet)

	// TODO: make a KEP and fix informers to always call the delete event handler on re-create
	if curDS.UID != oldDS.UID {
        // 如果当前 DaemonSet 对象的 UID 与旧 DaemonSet 对象的 UID 不同，则调用 deleteDaemonset 函数进行删除
		key, err := controller.KeyFunc(oldDS)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("couldn't get key for object %#v: %v", oldDS, err))
			return
		}
		dsc.deleteDaemonset(logger, cache.DeletedFinalStateUnknown{
			Key: key,
			Obj: oldDS,
		})
	}

	logger.V(4).Info("Updating daemon set", "daemonset", klog.KObj(oldDS))
	dsc.enqueueDaemonSet(curDS)
}

func (dsc *DaemonSetsController) deleteDaemonset(logger klog.Logger, obj interface{}) {
    // 断言ds 不是daemonset从DeletedFinalStateUnknown断言
	ds, ok := obj.(*apps.DaemonSet)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		ds, ok = tombstone.Obj.(*apps.DaemonSet)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a DaemonSet %#v", obj))
			return
		}
	}
	logger.V(4).Info("Deleting daemon set", "daemonset", klog.KObj(ds))

	key, err := controller.KeyFunc(ds)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %#v: %v", ds, err))
		return
	}

	// 删除 DaemonSet 对象的 expectations，这样如果我们创建了一个同名的 DaemonSet，它会从一个干净的状态开始
	dsc.expectations.DeleteExpectations(key)

	dsc.queue.Add(key)
}
```

#### history

```GO
func (dsc *DaemonSetsController) addHistory(logger klog.Logger, obj interface{}) {
	history := obj.(*apps.ControllerRevision)
	if history.DeletionTimestamp != nil {
		// 已经被标记为删除，则通过deleteHistory方法来删除此对象
		dsc.deleteHistory(logger, history)
		return
	}

	// 具有ControllerRef（即被一个DaemonSet控制）
	if controllerRef := metav1.GetControllerOf(history); controllerRef != nil {
        // 加入工作队列
		ds := dsc.resolveControllerRef(history.Namespace, controllerRef)
		if ds == nil {
			return
		}
		logger.V(4).Info("Observed a ControllerRevision", "controllerRevision", klog.KObj(history))
		return
	}

	// 获取控制此ControllerRevision对象的DaemonSet对象，如果存在则将其加入工作队列
	daemonSets := dsc.getDaemonSetsForHistory(logger, history)
	if len(daemonSets) == 0 {
		return
	}
	logger.V(4).Info("Orphan ControllerRevision added", "controllerRevision", klog.KObj(history))
	for _, ds := range daemonSets {
		dsc.enqueueDaemonSet(ds)
	}
}


func (dsc *DaemonSetsController) updateHistory(logger klog.Logger, old, cur interface{}) {
	curHistory := cur.(*apps.ControllerRevision)
	oldHistory := old.(*apps.ControllerRevision)
	if curHistory.ResourceVersion == oldHistory.ResourceVersion {
		// 如果curHistory和oldHistory的版本号相同，则不进行任何操作
		return
	}

	curControllerRef := metav1.GetControllerOf(curHistory)
	oldControllerRef := metav1.GetControllerOf(oldHistory)
	controllerRefChanged := !reflect.DeepEqual(curControllerRef, oldControllerRef)
	if controllerRefChanged && oldControllerRef != nil {
		// 对象发生变化 并且旧的不是空 把旧的加入队列
		if ds := dsc.resolveControllerRef(oldHistory.Namespace, oldControllerRef); ds != nil {
			dsc.enqueueDaemonSet(ds)
		}
	}

	if curControllerRef != nil {
        // 获取ds 并加入队列
		ds := dsc.resolveControllerRef(curHistory.Namespace, curControllerRef)
		if ds == nil {
			return
		}
		logger.V(4).Info("Observed an update to a ControllerRevision", "controllerRevision", klog.KObj(curHistory))
		dsc.enqueueDaemonSet(ds)
		return
	}

	labelChanged := !reflect.DeepEqual(curHistory.Labels, oldHistory.Labels)
	if labelChanged || controllerRefChanged {
        // label变化或者owner变化 获取ds 加入队列
		daemonSets := dsc.getDaemonSetsForHistory(logger, curHistory)
		if len(daemonSets) == 0 {
			return
		}
		logger.V(4).Info("Orphan ControllerRevision updated", "controllerRevision", klog.KObj(curHistory))
		for _, ds := range daemonSets {
			dsc.enqueueDaemonSet(ds)
		}
	}
}

func (dsc *DaemonSetsController) deleteHistory(logger klog.Logger, obj interface{}) {
	history, ok := obj.(*apps.ControllerRevision)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("Couldn't get object from tombstone %#v", obj))
			return
		}
		history, ok = tombstone.Obj.(*apps.ControllerRevision)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("Tombstone contained object that is not a ControllerRevision %#v", obj))
			return
		}
	}

	controllerRef := metav1.GetControllerOf(history)
	if controllerRef == nil {
		// 被删除ref 不关心 直接返回
		return
	}
    // 获取ds 加入队列
	ds := dsc.resolveControllerRef(history.Namespace, controllerRef)
	if ds == nil {
		return
	}
	logger.V(4).Info("ControllerRevision deleted", "controllerRevision", klog.KObj(history))
	dsc.enqueueDaemonSet(ds)
}
```

##### resolveControllerRef

```GO
func (dsc *DaemonSetsController) resolveControllerRef(namespace string, controllerRef *metav1.OwnerReference) *apps.DaemonSet {
	if controllerRef.Kind != controllerKind.Kind {
        // KING不相同 直接返回
		return nil
	}
	ds, err := dsc.dsLister.DaemonSets(namespace).Get(controllerRef.Name)
	if err != nil {
		return nil
	}
	if ds.UID != controllerRef.UID {
		// 如果不相同 直接返回
		return nil
	}
	return ds
}
```

##### getDaemonSetsForHistory

```go
func (dsc *DaemonSetsController) getDaemonSetsForHistory(logger klog.Logger, history *apps.ControllerRevision) []*apps.DaemonSet {
	daemonSets, err := dsc.dsLister.GetHistoryDaemonSets(history)
	if err != nil || len(daemonSets) == 0 {
		return nil
	}
	if len(daemonSets) > 1 {
		logger.V(4).Info("Found more than one DaemonSet selecting the ControllerRevision. This is potentially a user error",
			"controllerRevision", klog.KObj(history), "labels", history.Labels)
	}
	return daemonSets
}
```

#### pod

```go
func (dsc *DaemonSetsController) addPod(logger klog.Logger, obj interface{}) {
	pod := obj.(*v1.Pod)

	if pod.DeletionTimestamp != nil {
		// 当控制器管理器重启时，有可能会出现一个新的 pod 处于已经挂起删除状态。
		// 防止该 pod 成为创建观察对象。
		dsc.deletePod(logger, pod)
		return
	}

	// 如果该 pod 有一个控制器引用，则只需要关注这个引用。
	if controllerRef := metav1.GetControllerOf(pod); controllerRef != nil {
        // 解析控制器引用，找到对应的 DaemonSet
		ds := dsc.resolveControllerRef(pod.Namespace, controllerRef)
		if ds == nil {
			return
		}
		dsKey, err := controller.KeyFunc(ds)
		if err != nil {
			return
		}
		logger.V(4).Info("Pod added", "pod", klog.KObj(pod))
		dsc.expectations.CreationObserved(dsKey)
        // 将该 DaemonSet 加入队列等待处理。
		dsc.enqueueDaemonSet(ds)
		return
	}

	// 否则，它是个孤儿 pod。获取所有匹配的 DaemonSet 列表并同步它们，
	// 以查看是否有任何 DaemonSet 愿意收养它。
	// 不观察创建，因为没有控制器需要等待孤儿 pod 的创建。
	dss := dsc.getDaemonSetsForPod(pod)
	if len(dss) == 0 {
		return
	}
	logger.V(4).Info("Orphan Pod added", "pod", klog.KObj(pod))
	for _, ds := range dss {
		dsc.enqueueDaemonSet(ds)
	}
}

func (dsc *DaemonSetsController) updatePod(logger klog.Logger, old, cur interface{}) {
	curPod := cur.(*v1.Pod)
	oldPod := old.(*v1.Pod)
	if curPod.ResourceVersion == oldPod.ResourceVersion {
		// 周期性的重新同步将发送更新事件以处理所有已知的 pods。
		// 两个不同版本的同一 pod 总是具有不同的 RVs。
		return
	}

	if curPod.DeletionTimestamp != nil {
		// 当 pod 被正常删除时，其删除时间戳首先被修改以反映优雅的等待时间，
        // 并在此时间过去后，kubelet 实际上将其从存储中删除。
        // 我们会收到更新以修改删除时间戳，并期望 ds 尽快创建更多副本，而不是等待 kubelet 实际上删除 pod。
		dsc.deletePod(logger, curPod)
		return
	}

	curControllerRef := metav1.GetControllerOf(curPod)
	oldControllerRef := metav1.GetControllerOf(oldPod)
    // 控制器引用是否发生了变化
	controllerRefChanged := !reflect.DeepEqual(curControllerRef, oldControllerRef)
	if controllerRefChanged && oldControllerRef != nil {
		// 控制器引用已更改。同步旧控制器（如果有）。
		if ds := dsc.resolveControllerRef(oldPod.Namespace, oldControllerRef); ds != nil {
			dsc.enqueueDaemonSet(ds)
		}
	}

	// 如果它有一个 ControllerRef，则只需要关注这个引用。
	if curControllerRef != nil {
        // 解析控制器引用，找到对应的 DaemonSet
		ds := dsc.resolveControllerRef(curPod.Namespace, curControllerRef)
		if ds == nil {
			return
		}
		logger.V(4).Info("Pod updated", "pod", klog.KObj(curPod))
        // 将该 DaemonSet 加入队列等待处理。
		dsc.enqueueDaemonSet(ds)
		changedToReady := !podutil.IsPodReady(oldPod) && podutil.IsPodReady(curPod)
		// 如果 DaemonSet 的 minReadySeconds 大于 0，表示要等待一段时间后再触发同步操作。
		// 详细信息 https://github.com/kubernetes/kubernetes/pull/38076。
		if changedToReady && ds.Spec.MinReadySeconds > 0 {
			// 添加一秒钟以避免 AddAfter 中的毫秒偏差。
			// 详细信息 https://github.com/kubernetes/kubernetes/issues/39785#issuecomment-279959133。
			dsc.enqueueDaemonSetAfter(ds, (time.Duration(ds.Spec.MinReadySeconds)*time.Second)+time.Second)
		}
		return
	}

	// 否则，它是个孤儿 pod。如果有任何更改，同步匹配的控制器以查看是否有人现在想要收养它。
	dss := dsc.getDaemonSetsForPod(curPod)
	if len(dss) == 0 {
		return
	}
	logger.V(4).Info("Orphan Pod updated", "pod", klog.KObj(curPod))
    // 标签是否已更改
	labelChanged := !reflect.DeepEqual(curPod.Labels, oldPod.Labels)
	if labelChanged || controllerRefChanged {
		for _, ds := range dss {
            // 将该 DaemonSet 加入队列等待处理。
			dsc.enqueueDaemonSet(ds)
		}
	}
}

func (dsc *DaemonSetsController) deletePod(logger klog.Logger, obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		pod, ok = tombstone.Obj.(*v1.Pod)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a pod %#v", obj))
			return
		}
	}
	
	controllerRef := metav1.GetControllerOf(pod)
	if controllerRef == nil {
		// 没有控制器需要关心已删除的孤儿 pod。
		return
	}
    // 解析控制器引用，找到对应的 DaemonSet
	ds := dsc.resolveControllerRef(pod.Namespace, controllerRef)
	if ds == nil {
		return
	}
	dsKey, err := controller.KeyFunc(ds)
	if err != nil {
		return
	}
	logger.V(4).Info("Pod deleted", "pod", klog.KObj(pod))
	dsc.expectations.DeletionObserved(dsKey)
    // 加入队列
	dsc.enqueueDaemonSet(ds)
}
```

##### getDaemonSetsForPod

```GO
func (dsc *DaemonSetsController) getDaemonSetsForPod(pod *v1.Pod) []*apps.DaemonSet {
	sets, err := dsc.dsLister.GetPodDaemonSets(pod)
	if err != nil {
		return nil
	}
	if len(sets) > 1 {
		utilruntime.HandleError(fmt.Errorf("user error! more than one daemon is selecting pods with labels: %+v", pod.Labels))
	}
	return sets
}
```

##### enqueueDaemonSetAfter

```GO
func (dsc *DaemonSetsController) enqueueDaemonSetAfter(obj interface{}, after time.Duration) {
	key, err := controller.KeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %+v: %v", obj, err))
		return
	}

	// TODO: Handle overlapping controllers better. See comment in ReplicationManager.
	dsc.queue.AddAfter(key, after)
}
```

#### node

```go
func (dsc *DaemonSetsController) addNode(logger klog.Logger, obj interface{}) {
	// TODO: 这些 enqueues 中传递一个提示会很好，这样每个 ds 只会检查添加的节点（除非它还有其他工作要做）。
	// 获取所有的 DaemonSet
	dsList, err := dsc.dsLister.List(labels.Everything())
	if err != nil {
		logger.V(4).Info("Error enqueueing daemon sets", "err", err)
		return
	}
	node := obj.(*v1.Node)
    // 遍历 DaemonSet，如果该节点应该运行此 DaemonSet 的 pod，则将该 DaemonSet 加入队列等待处理。
	for _, ds := range dsList {
		if shouldRun, _ := NodeShouldRunDaemonPod(node, ds); shouldRun {
			dsc.enqueueDaemonSet(ds)
		}
	}
}

func (dsc *DaemonSetsController) updateNode(logger klog.Logger, old, cur interface{}) {
	oldNode := old.(*v1.Node)
	curNode := cur.(*v1.Node)
    // 检查是否应忽略此节点的更新事件
	if shouldIgnoreNodeUpdate(*oldNode, *curNode) {
		return
	}

	dsList, err := dsc.dsLister.List(labels.Everything())
	if err != nil {
		logger.V(4).Info("Error listing daemon sets", "err", err)
		return
	}
	// TODO: 这些 enqueues 中传递一个提示会很好，这样每个 ds 只会检查添加的节点（除非它还有其他工作要做）
	for _, ds := range dsList {
		oldShouldRun, oldShouldContinueRunning := NodeShouldRunDaemonPod(oldNode, ds)
		currentShouldRun, currentShouldContinueRunning := NodeShouldRunDaemonPod(curNode, ds)
        // 如果该节点应该运行或继续运行此 DaemonSet 的 pod 状态发生了变化，则将该 DaemonSet 加入队列等待处理。
		if (oldShouldRun != currentShouldRun) || (oldShouldContinueRunning != currentShouldContinueRunning) {
			dsc.enqueueDaemonSet(ds)
		}
	}
}
```

##### NodeShouldRunDaemonPod

```go
func NodeShouldRunDaemonPod(node *v1.Node, ds *apps.DaemonSet) (bool, bool) {
    // 根据 DaemonSet 和节点创建一个 Pod
	pod := NewPod(ds, node.Name)

	// 如果 DaemonSet 指定了节点名称，则检查它是否与 node.Name 匹配。
    if !(ds.Spec.Template.Spec.NodeName == "" || ds.Spec.Template.Spec.NodeName == node.Name) {
        return false, false
    }

    // 获取节点的污点信息
    taints := node.Spec.Taints
    // 根据一些策略（如节点名称、节点亲和性、污点）来判断 Pod 是否可以调度到该节点上运行
    fitsNodeName, fitsNodeAffinity, fitsTaints := predicates(pod, node, taints)
    if !fitsNodeName || !fitsNodeAffinity {
        return false, false
    }

    if !fitsTaints {
        // 如果 Pod 容忍了 NoExecute 污点，则应继续运行已调度的 Daemon Pod。
        _, hasUntoleratedTaint := v1helper.FindMatchingUntoleratedTaint(taints, pod.Spec.Tolerations, func(t *v1.Taint) bool {
            return t.Effect == v1.TaintEffectNoExecute
        })
        return false, !hasUntoleratedTaint
    }

    // 返回是否应该运行该 DaemonSet 的 pod 以及该 pod 是否应该继续运行的标志
    return true, true
}
```

###### NewPod

```go
func NewPod(ds *apps.DaemonSet, nodeName string) *v1.Pod {
	newPod := &v1.Pod{Spec: ds.Spec.Template.Spec, ObjectMeta: ds.Spec.Template.ObjectMeta}
	newPod.Namespace = ds.Namespace
	newPod.Spec.NodeName = nodeName

	// Added default tolerations for DaemonSet pods.
	util.AddOrUpdateDaemonPodTolerations(&newPod.Spec)

	return newPod
}
```

###### AddOrUpdateDaemonPodTolerations

```go
// 添加一些容忍度
func AddOrUpdateDaemonPodTolerations(spec *v1.PodSpec) {
	// DaemonSet pods shouldn't be deleted by NodeController in case of node problems.
	// Add infinite toleration for taint notReady:NoExecute here
	// to survive taint-based eviction enforced by NodeController
	// when node turns not ready.
	v1helper.AddOrUpdateTolerationInPodSpec(spec, &v1.Toleration{
		Key:      v1.TaintNodeNotReady,
		Operator: v1.TolerationOpExists,
		Effect:   v1.TaintEffectNoExecute,
	})

	// DaemonSet pods shouldn't be deleted by NodeController in case of node problems.
	// Add infinite toleration for taint unreachable:NoExecute here
	// to survive taint-based eviction enforced by NodeController
	// when node turns unreachable.
	v1helper.AddOrUpdateTolerationInPodSpec(spec, &v1.Toleration{
		Key:      v1.TaintNodeUnreachable,
		Operator: v1.TolerationOpExists,
		Effect:   v1.TaintEffectNoExecute,
	})

	// According to TaintNodesByCondition feature, all DaemonSet pods should tolerate
	// MemoryPressure, DiskPressure, PIDPressure, Unschedulable and NetworkUnavailable taints.
	v1helper.AddOrUpdateTolerationInPodSpec(spec, &v1.Toleration{
		Key:      v1.TaintNodeDiskPressure,
		Operator: v1.TolerationOpExists,
		Effect:   v1.TaintEffectNoSchedule,
	})

	v1helper.AddOrUpdateTolerationInPodSpec(spec, &v1.Toleration{
		Key:      v1.TaintNodeMemoryPressure,
		Operator: v1.TolerationOpExists,
		Effect:   v1.TaintEffectNoSchedule,
	})

	v1helper.AddOrUpdateTolerationInPodSpec(spec, &v1.Toleration{
		Key:      v1.TaintNodePIDPressure,
		Operator: v1.TolerationOpExists,
		Effect:   v1.TaintEffectNoSchedule,
	})

	v1helper.AddOrUpdateTolerationInPodSpec(spec, &v1.Toleration{
		Key:      v1.TaintNodeUnschedulable,
		Operator: v1.TolerationOpExists,
		Effect:   v1.TaintEffectNoSchedule,
	})

	if spec.HostNetwork {
		v1helper.AddOrUpdateTolerationInPodSpec(spec, &v1.Toleration{
			Key:      v1.TaintNodeNetworkUnavailable,
			Operator: v1.TolerationOpExists,
			Effect:   v1.TaintEffectNoSchedule,
		})
	}
}
```

###### predicates

```GO
func predicates(pod *v1.Pod, node *v1.Node, taints []v1.Taint) (fitsNodeName, fitsNodeAffinity, fitsTaints bool) {
	fitsNodeName = len(pod.Spec.NodeName) == 0 || pod.Spec.NodeName == node.Name
	// 判断节点是否符合 DaemonSet 中定义的亲和性和反亲和性规则
	// 忽略解析错误以保持向后兼容性
	fitsNodeAffinity, _ = nodeaffinity.GetRequiredNodeAffinity(pod).Match(node)
    
    // 判断该节点上是否有未容忍的污点
	_, hasUntoleratedTaint := v1helper.FindMatchingUntoleratedTaint(taints, pod.Spec.Tolerations, func(t *v1.Taint) bool {
		return t.Effect == v1.TaintEffectNoExecute || t.Effect == v1.TaintEffectNoSchedule
	})
	fitsTaints = !hasUntoleratedTaint
	return
}
```

###### shouldIgnoreNodeUpdate

```GO
func shouldIgnoreNodeUpdate(oldNode, curNode v1.Node) bool {
    // 如果旧节点和当前节点的状态条件不同，则不忽略更新
	if !nodeInSameCondition(oldNode.Status.Conditions, curNode.Status.Conditions) {
		return false
	}
	oldNode.ResourceVersion = curNode.ResourceVersion
	oldNode.Status.Conditions = curNode.Status.Conditions
	return apiequality.Semantic.DeepEqual(oldNode, curNode)
}
```

###### nodeInSameCondition

```GO
func nodeInSameCondition(old []v1.NodeCondition, cur []v1.NodeCondition) bool {
	if len(old) == 0 && len(cur) == 0 {
		return true
	}

	c1map := map[v1.NodeConditionType]v1.ConditionStatus{}
	for _, c := range old {
		if c.Status == v1.ConditionTrue {
			c1map[c.Type] = c.Status
		}
	}

	for _, c := range cur {
		if c.Status != v1.ConditionTrue {
			continue
		}

		if _, found := c1map[c.Type]; !found {
			return false
		}

		delete(c1map, c.Type)
	}

	return len(c1map) == 0
}
```

## Run

```go
func (dsc *DaemonSetsController) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()

	dsc.eventBroadcaster.StartStructuredLogging(0)
	dsc.eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: dsc.kubeClient.CoreV1().Events("")})
	defer dsc.eventBroadcaster.Shutdown()

	defer dsc.queue.ShutDown()

	logger := klog.FromContext(ctx)
	logger.Info("Starting daemon sets controller")
	defer logger.Info("Shutting down daemon sets controller")

	if !cache.WaitForNamedCacheSync("daemon sets", ctx.Done(), dsc.podStoreSynced, dsc.nodeStoreSynced, dsc.historyStoreSynced, dsc.dsStoreSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, dsc.runWorker, time.Second)
	}

	go wait.Until(dsc.failedPodsBackoff.GC, BackoffGCInterval, ctx.Done())

	<-ctx.Done()
}
```

## dsc.failedPodsBackoff.GC

```go
type Backoff struct {
	sync.RWMutex
	Clock           clock.Clock
    // 默认持续时间
	defaultDuration time.Duration
    // 最大持续时间，即后退持续时间的上限
	maxDuration     time.Duration
    // 为每个项目存储后退持续时间的映射，以项目的唯一标识符作为键
	perItemBackoff  map[string]*backoffEntry
	rand            *rand.Rand
	maxJitterFactor float64
}

type backoffEntry struct {
	backoff    time.Duration
	lastUpdate time.Time
}
```

```go
// 根据给定的 ID 获取该条目的当前 backoff 时间间隔
func (p *Backoff) Get(id string) time.Duration {
	p.RLock()
	defer p.RUnlock()
	var delay time.Duration
	entry, ok := p.perItemBackoff[id]
	if ok {
		delay = entry.backoff
	}
	return delay
}

// 将给定 ID 的 backoff 时间间隔增加到下一个级别。如果当前时间已超过 maxDuration，则重新计算默认时间间隔。
// 如果 ID 不存在，则创建新的条目，并设置为默认时间间隔。如果存在，则将 backoff 时间间隔加倍，并添加一些随机抖动。
func (p *Backoff) Next(id string, eventTime time.Time) {
	p.Lock()
	defer p.Unlock()
	entry, ok := p.perItemBackoff[id]
	if !ok || hasExpired(eventTime, entry.lastUpdate, p.maxDuration) {
		entry = p.initEntryUnsafe(id)
		entry.backoff += p.jitter(entry.backoff)
	} else {
		delay := entry.backoff * 2       // exponential
		delay += p.jitter(entry.backoff) // add some jitter to the delay
		entry.backoff = time.Duration(integer.Int64Min(int64(delay), int64(p.maxDuration)))
	}
	entry.lastUpdate = p.Clock.Now()
}

//   强制清除给定 ID 的所有 backoff 数据
func (p *Backoff) Reset(id string) {
	p.Lock()
	defer p.Unlock()
	delete(p.perItemBackoff, id)
}

// 如果从事件时间到当前时间经过的时间小于当前 backoff 窗口，则返回 True。否则返回 False。
func (p *Backoff) IsInBackOffSince(id string, eventTime time.Time) bool {
	p.RLock()
	defer p.RUnlock()
	entry, ok := p.perItemBackoff[id]
	if !ok {
		return false
	}
	if hasExpired(eventTime, entry.lastUpdate, p.maxDuration) {
		return false
	}
	return p.Clock.Since(eventTime) < entry.backoff
}

// 如果从上次更新到事件时间经过的时间小于当前 backoff 窗口，则返回 True。否则返回 False
func (p *Backoff) IsInBackOffSinceUpdate(id string, eventTime time.Time) bool {
	p.RLock()
	defer p.RUnlock()
	entry, ok := p.perItemBackoff[id]
	if !ok {
		return false
	}
	if hasExpired(eventTime, entry.lastUpdate, p.maxDuration) {
		return false
	}
	return eventTime.Sub(entry.lastUpdate) < entry.backoff
}

// 垃圾回收，删除已过期的记录
func (p *Backoff) GC() {
	p.Lock()
	defer p.Unlock()
	now := p.Clock.Now()
	for id, entry := range p.perItemBackoff {
		if now.Sub(entry.lastUpdate) > p.maxDuration*2 {
			// GC when entry has not been updated for 2*maxDuration
			delete(p.perItemBackoff, id)
		}
	}
}

// 删除给定 ID 的条目
func (p *Backoff) DeleteEntry(id string) {
	p.Lock()
	defer p.Unlock()
	delete(p.perItemBackoff, id)
}

// 私有函数，用于在锁定 Backoff 后初始化新条目。如果 ID 已存在，则返回该条目。如果不存在，则创建一个新的默认条目并返回
func (p *Backoff) initEntryUnsafe(id string) *backoffEntry {
	entry := &backoffEntry{backoff: p.defaultDuration}
	p.perItemBackoff[id] = entry
	return entry
}

// 生成随机抖动的时间间隔，用于添加到 backoff 时间间隔中
func (p *Backoff) jitter(delay time.Duration) time.Duration {
	if p.rand == nil {
		return 0
	}

	return time.Duration(p.rand.Float64() * p.maxJitterFactor * float64(delay))
}

// 如果从上次更新到事件时间超过 2 倍的 maxDuration，则返回 True。否则返回 False。
func hasExpired(eventTime time.Time, lastUpdate time.Time, maxDuration time.Duration) bool {
	return eventTime.Sub(lastUpdate) > maxDuration*2 // consider stable if it's ok for twice the maxDuration
}
```

## runWorker

```go
func (dsc *DaemonSetsController) runWorker(ctx context.Context) {
	for dsc.processNextWorkItem(ctx) {
	}
}

func (dsc *DaemonSetsController) processNextWorkItem(ctx context.Context) bool {
	dsKey, quit := dsc.queue.Get()
	if quit {
		return false
	}
	defer dsc.queue.Done(dsKey)

	err := dsc.syncHandler(ctx, dsKey.(string))
	if err == nil {
		dsc.queue.Forget(dsKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with : %v", dsKey, err))
	dsc.queue.AddRateLimited(dsKey)

	return true
}
```

syncHandler在New的是时候赋值的

```GO
func (dsc *DaemonSetsController) syncDaemonSet(ctx context.Context, key string) error {
	logger := klog.FromContext(ctx)
    // 同步开始的时间
	startTime := dsc.failedPodsBackoff.Clock.Now()

	defer func() {
		logger.V(4).Info("Finished syncing daemon set", "daemonset", key, "time", dsc.failedPodsBackoff.Clock.Now().Sub(startTime))
	}()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
    // 获取ds 
	ds, err := dsc.dsLister.DaemonSets(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		logger.V(3).Info("Daemon set has been deleted", "daemonset", key)
        // 从期望列表中删除该对象
		dsc.expectations.DeleteExpectations(key)
		return nil
	}
	if err != nil {
		return fmt.Errorf("unable to retrieve ds %v from store: %v", key, err)
	}
	
    // 获取所有node
	nodeList, err := dsc.nodeLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("couldn't get list of nodes when syncing daemon set %#v: %v", ds, err)
	}
	
    // 检查 DaemonSet 对象的选择器是否为空。如果是，则会记录一个事件并返回 nil
	everything := metav1.LabelSelector{}
	if reflect.DeepEqual(ds.Spec.Selector, &everything) {
		dsc.eventRecorder.Eventf(ds, v1.EventTypeWarning, SelectingAllReason, "This daemon set is selecting all pods. A non-empty selector is required.")
		return nil
	}

	dsKey, err := controller.KeyFunc(ds)
	if err != nil {
		return fmt.Errorf("couldn't get key for object %#v: %v", ds, err)
	}

	// 如果 DaemonSet 对象已经被删除，则直接返回 nil。
	if ds.DeletionTimestamp != nil {
		return nil
	}

	 // 构造 DaemonSet 的历史版本，并获取当前版本的 hash 值
	cur, old, err := dsc.constructHistory(ctx, ds)
	if err != nil {
		return fmt.Errorf("failed to construct revisions of DaemonSet: %v", err)
	}
	hash := cur.Labels[apps.DefaultDaemonSetUniqueLabelKey]
	
    // 如果对应 DaemonSet 的期望状态未达成，只更新状态
	if !dsc.expectations.SatisfiedExpectations(dsKey) {
		// 只更新状态，不提升 observedGeneration，因为控制器并未处理该对象的当前版本
		return dsc.updateDaemonSetStatus(ctx, ds, nodeList, hash, false)
	}
	
    // 更新 DaemonSet 对象及其状态
	err = dsc.updateDaemonSet(ctx, ds, nodeList, hash, dsKey, old)
	statusErr := dsc.updateDaemonSetStatus(ctx, ds, nodeList, hash, true)
	switch {
	case err != nil && statusErr != nil:
		// 如果出现错误，并更新状态失败，则记录日志并返回原始错误
		logger.Error(statusErr, "Failed to update status", "daemonSet", klog.KObj(ds))
		return err
	case err != nil: 
        // 更新 DaemonSet 对象失败，则返回错误
		return err
	case statusErr != nil:
        // 更新状态失败，则返回错误
		return statusErr
	}

	return nil
}
```

### constructHistory

```GO
// 构造 DaemonSet 的历史版本，并返回当前版本和旧版本的数组
func (dsc *DaemonSetsController) constructHistory(ctx context.Context, ds *apps.DaemonSet) (cur *apps.ControllerRevision, old []*apps.ControllerRevision, err error) {
	var histories []*apps.ControllerRevision
	var currentHistories []*apps.ControllerRevision
    // 获取 DaemonSet 的历史版本列表
	histories, err = dsc.controlledHistories(ctx, ds)
	if err != nil {
		return nil, nil, err
	}
    
    // 遍历历史版本列表，为每个版本加上唯一标识符，分为当前版本和旧版本
	for _, history := range histories {
		// 如果历史版本中没有唯一标识符，则添加一个唯一标识符
        // 我们使用历史版本的名称而不是计算哈希值，以便我们不必担心哈希碰撞
		if _, ok := history.Labels[apps.DefaultDaemonSetUniqueLabelKey]; !ok {
			toUpdate := history.DeepCopy()
			toUpdate.Labels[apps.DefaultDaemonSetUniqueLabelKey] = toUpdate.Name
			history, err = dsc.kubeClient.AppsV1().ControllerRevisions(ds.Namespace).Update(ctx, toUpdate, metav1.UpdateOptions{})
			if err != nil {
				return nil, nil, err
			}
		}
		// 将历史版本与当前 DaemonSet 版本进行比较，区分当前版本和旧版本
		found := false
		found, err = Match(ds, history)
		if err != nil {
			return nil, nil, err
		}
		if found {
			currentHistories = append(currentHistories, history)
		} else {
			old = append(old, history)
		}
	}
	
    // 计算当前版本号
	currRevision := maxRevision(old) + 1
	switch len(currentHistories) {
	case 0:
		// 如果没有找到当前版本，则创建一个新版本
		cur, err = dsc.snapshot(ctx, ds, currRevision)
		if err != nil {
			return nil, nil, err
		}
	default:
        // 如果找到了当前版本，则从中选择唯一的一个
		cur, err = dsc.dedupCurHistories(ctx, ds, currentHistories)
		if err != nil {
			return nil, nil, err
		}
		// 如果需要，则更新版本号
		if cur.Revision < currRevision {
			toUpdate := cur.DeepCopy()
			toUpdate.Revision = currRevision
			_, err = dsc.kubeClient.AppsV1().ControllerRevisions(ds.Namespace).Update(ctx, toUpdate, metav1.UpdateOptions{})
			if err != nil {
				return nil, nil, err
			}
		}
	}
	return cur, old, err
}
```

#### controlledHistories

```GO
// 获取 DaemonSet 对象关联的所有 ControllerRevision 历史版本
func (dsc *DaemonSetsController) controlledHistories(ctx context.Context, ds *apps.DaemonSet) ([]*apps.ControllerRevision, error) {
    // 将 Selector 转换为 Selector 对象
	selector, err := metav1.LabelSelectorAsSelector(ds.Spec.Selector)
	if err != nil {
		return nil, err
	}

	// 获取 DaemonSet 关联的 ControllerRevision 历史版本，包括不再与 Selector 匹配但具有指向控制器的 ControllerRef 的版本
	histories, err := dsc.historyLister.ControllerRevisions(ds.Namespace).List(labels.Everything())
	if err != nil {
		return nil, err
	}
	// 如果尝试进行 Adoption，则需要在列出 Pods 之后的某个时候使用未缓存的法定读取重新检查删除时间戳（请参见＃42639）。
	canAdoptFunc := controller.RecheckDeletionTimestamp(func(ctx context.Context) (metav1.Object, error) {
		fresh, err := dsc.kubeClient.AppsV1().DaemonSets(ds.Namespace).Get(ctx, ds.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if fresh.UID != ds.UID {
			return nil, fmt.Errorf("original DaemonSet %v/%v is gone: got uid %v, wanted %v", ds.Namespace, ds.Name, fresh.UID, ds.UID)
		}
		return fresh, nil
	})
	 // 使用 ControllerRefManager 进行 Adoption 或 Orphan 操作
    // 和replicaset-controller deployment-controller逻辑差不多
	cm := controller.NewControllerRevisionControllerRefManager(dsc.crControl, ds, selector, controllerKind, canAdoptFunc)
    // 将 ControllerRevision 历史版本与该控制器的 ControllerRef 进行匹配并返回
	return cm.ClaimControllerRevisions(ctx, histories)
}
```

##### RecheckDeletionTimestamp

```GO
func RecheckDeletionTimestamp(getObject func(context.Context) (metav1.Object, error)) func(context.Context) error {
	return func(ctx context.Context) error {
		obj, err := getObject(ctx)
		if err != nil {
			return fmt.Errorf("can't recheck DeletionTimestamp: %v", err)
		}
		if obj.GetDeletionTimestamp() != nil {
			return fmt.Errorf("%v/%v has just been deleted at %v", obj.GetNamespace(), obj.GetName(), obj.GetDeletionTimestamp())
		}
		return nil
	}
}
```

#### Match

```GO
func Match(ds *apps.DaemonSet, history *apps.ControllerRevision) (bool, error) {
	patch, err := getPatch(ds)
	if err != nil {
		return false, err
	}
	return bytes.Equal(patch, history.Data.Raw), nil
}
```

##### getPatch

```GO
func getPatch(ds *apps.DaemonSet) ([]byte, error) {
	dsBytes, err := json.Marshal(ds)
	if err != nil {
		return nil, err
	}
	var raw map[string]interface{}
	err = json.Unmarshal(dsBytes, &raw)
	if err != nil {
		return nil, err
	}
	objCopy := make(map[string]interface{})
	specCopy := make(map[string]interface{})

	// Create a patch of the DaemonSet that replaces spec.template
	spec := raw["spec"].(map[string]interface{})
	template := spec["template"].(map[string]interface{})
	specCopy["template"] = template
	template["$patch"] = "replace"
	objCopy["spec"] = specCopy
	patch, err := json.Marshal(objCopy)
	return patch, err
}
```

#### maxRevision

```GO
func maxRevision(histories []*apps.ControllerRevision) int64 {
	max := int64(0)
	for _, history := range histories {
		if history.Revision > max {
			max = history.Revision
		}
	}
	return max
}
```

#### snapshot

```GO
// 创建新的 ControllerRevision 历史版本
func (dsc *DaemonSetsController) snapshot(ctx context.Context, ds *apps.DaemonSet, revision int64) (*apps.ControllerRevision, error) {
    // 获取 DaemonSet 的 JSON 表示，并将其转换为 JSON 补丁
	patch, err := getPatch(ds)
	if err != nil {
		return nil, err
	}
    // 计算使用指定的 DaemonSet 模板和碰撞计数值来生成唯一哈希值
	hash := controller.ComputeHash(&ds.Spec.Template, ds.Status.CollisionCount)
    // 构造新的 ControllerRevision 对象
	name := ds.Name + "-" + hash
	history := &apps.ControllerRevision{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       ds.Namespace,
			Labels:          labelsutil.CloneAndAddLabel(ds.Spec.Template.Labels, apps.DefaultDaemonSetUniqueLabelKey, hash),
			Annotations:     ds.Annotations,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(ds, controllerKind)},
		},
		Data:     runtime.RawExtension{Raw: patch},
		Revision: revision,
	}
	// 将 ControllerRevision 对象创建到 Kubernetes API 服务器
	history, err = dsc.kubeClient.AppsV1().ControllerRevisions(ds.Namespace).Create(ctx, history, metav1.CreateOptions{})
	if outerErr := err; errors.IsAlreadyExists(outerErr) {
		logger := klog.FromContext(ctx)
		 // TODO: Is it okay to get from historyLister?
        // 如果 ControllerRevision 已经存在，则尝试更新或使用已存在的 ControllerRevision。
		existedHistory, getErr := dsc.kubeClient.AppsV1().ControllerRevisions(ds.Namespace).Get(ctx, name, metav1.GetOptions{})
		if getErr != nil {
			return nil, getErr
		}
		// 检查当前 DaemonSet 是否已经创建
		done, matchErr := Match(ds, existedHistory)
		if matchErr != nil {
			return nil, matchErr
		}
		if done {
			return existedHistory, nil
		}

		 // 如果存在名称冲突，则处理名称冲突并重试
		currDS, getErr := dsc.kubeClient.AppsV1().DaemonSets(ds.Namespace).Get(ctx, ds.Name, metav1.GetOptions{})
		if getErr != nil {
			return nil, getErr
		}
		// If the collision count used to compute hash was in fact stale, there's no need to bump collision count; retry again
		if !reflect.DeepEqual(currDS.Status.CollisionCount, ds.Status.CollisionCount) {
			return nil, fmt.Errorf("found a stale collision count (%d, expected %d) of DaemonSet %q while processing; will retry until it is updated", ds.Status.CollisionCount, currDS.Status.CollisionCount, ds.Name)
		}
		if currDS.Status.CollisionCount == nil {
			currDS.Status.CollisionCount = new(int32)
		}
		*currDS.Status.CollisionCount++
		_, updateErr := dsc.kubeClient.AppsV1().DaemonSets(ds.Namespace).UpdateStatus(ctx, currDS, metav1.UpdateOptions{})
		if updateErr != nil {
			return nil, updateErr
		}
		logger.V(2).Info("Found a hash collision for DaemonSet - bumping collisionCount to resolve it", "daemonset", klog.KObj(ds), "collisionCount", *currDS.Status.CollisionCount)
		return nil, outerErr
	}
	return history, err
}
```

##### ComputeHash

```GO
func ComputeHash(template *v1.PodTemplateSpec, collisionCount *int32) string {
	podTemplateSpecHasher := fnv.New32a()
	hashutil.DeepHashObject(podTemplateSpecHasher, *template)

	// Add collisionCount in the hash if it exists.
	if collisionCount != nil {
		collisionCountBytes := make([]byte, 8)
		binary.LittleEndian.PutUint32(collisionCountBytes, uint32(*collisionCount))
		podTemplateSpecHasher.Write(collisionCountBytes)
	}

	return rand.SafeEncodeString(fmt.Sprint(podTemplateSpecHasher.Sum32()))
}
```

#### dedupCurHistories

```GO
// 对当前的 DaemonSet 历史版本进行去重，保留最新的版本，并对其他版本所对应的 Pod 进行重新标记，使其与最新版本关联
func (dsc *DaemonSetsController) dedupCurHistories(ctx context.Context, ds *apps.DaemonSet, curHistories []*apps.ControllerRevision) (*apps.ControllerRevision, error) {
	// 如果当前历史版本只有一个，则直接返回该版本
	if len(curHistories) == 1 {
		return curHistories[0], nil
	}

	var maxRevision int64
	var keepCur *apps.ControllerRevision
	// 找到最新的版本，即 Revision 最大的版本
	for _, cur := range curHistories {
		if cur.Revision >= maxRevision {
			keepCur = cur
			maxRevision = cur.Revision
		}
	}

	// Clean up duplicates and relabel pods
	// 对其他版本所对应的 Pod 进行重新标记
	for _, cur := range curHistories {
		if cur.Name == keepCur.Name {
			continue
		}

		// Relabel pods before dedup
		// 获取当前 DaemonSet 对应的 Pod
		pods, err := dsc.getDaemonPods(ctx, ds)
		if err != nil {
			return nil, err
		}
		// 遍历 Pod，并将标记不是最新版本的 Pod 进行重新标记，使其与最新版本关联
		for _, pod := range pods {
			if pod.Labels[apps.DefaultDaemonSetUniqueLabelKey] != keepCur.Labels[apps.DefaultDaemonSetUniqueLabelKey] {
				patchRaw := map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels": map[string]interface{}{
							apps.DefaultDaemonSetUniqueLabelKey: keepCur.Labels[apps.DefaultDaemonSetUniqueLabelKey],
						},
					},
				}
				patchJson, err := json.Marshal(patchRaw)
				if err != nil {
					return nil, err
				}
				_, err = dsc.kubeClient.CoreV1().Pods(ds.Namespace).Patch(ctx, pod.Name, types.MergePatchType, patchJson, metav1.PatchOptions{})
				if err != nil {
					return nil, err
				}
			}
		}
		// Remove duplicates
		// 删除其他版本的 ControllerRevision
		err = dsc.kubeClient.AppsV1().ControllerRevisions(ds.Namespace).Delete(ctx, cur.Name, metav1.DeleteOptions{})
		if err != nil {
			return nil, err
		}
	}

	// 返回最新版本的 ControllerRevision
	return keepCur, nil
}
```

