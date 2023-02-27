---
title: "kubernetes client-go功能介绍"
date: 2023-02-26T12:03:20+08:00
draft: false
toc: true
categories: 
    - cloud
tags: 
    - cloud
    - kubernetes
authors:
    - haiyux
---

## client-go是什么？

client-go是Kubernetes官方提供的Go语言客户端库，用于与Kubernetes API服务器交互。使用client-go，您可以编写Go语言程序来创建、修改和删除Kubernetes对象，如Pod、Deployment、Service等。

## 作用

client-go的主要功能包括：

1. 连接Kubernetes API服务器：client-go提供了一个API客户端，用于连接Kubernetes API服务器。
2. 对象管理：client-go提供了一组API，用于创建、读取、更新和删除Kubernetes对象，如Pod、Deployment、Service等。
3. Watch API：client-go提供了一个Watch API，可以用于监视Kubernetes对象的变化。
4. 命名空间支持：client-go支持多个命名空间，并提供了一组API，用于管理命名空间。
5. 认证和授权：client-go提供了一组API，用于执行身份验证和授权，以确保只有授权的用户才能对Kubernetes对象进行操作。

client-go是使用Kubernetes API的标准方式，是Kubernetes生态系统中的重要组成部分。

## api client

client-go 中包含四种client，`RestClient`, `ClientSet`，`DynamicClient`和`DiscoveryClient`。

![client-go-client](/images/client-go-client.jpg)

`ClientSet`，`DynamicClient`，`DiscoveryClient`都是`RestClient`上的封装

### RestClient

RestClient是最基础的客户端，它基于HTTP请求进行了封装，实现了RESTful API。使用RESTClient提供的RESTful方法，如Get()、Put()、Post()和Delete()，可以直接与API进行交互。同时，它支持JSON和Protocol Buffers，并支持所有原生资源和自定义资源定义（CRDs）。然而，为了更加优雅地处理API交互，一般需要进一步封装，通过Clientset对RESTClient进行封装，然后再对外提供接口和服务。

```go
package main

import (
	"context"
	"fmt"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)


func main() {
	// 使用kubeconfig生成配置
	config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
	if err != nil {
		panic(err)
	}
	config.APIPath = "api"
	config.GroupVersion = &corev1.SchemeGroupVersion
	config.NegotiatedSerializer = scheme.Codecs

	// 生成restClient
	restClient, err := rest.RESTClientFor(config)
	if err != nil {
		panic(err)
	}

	rest := &corev1.PodList{}
	if err = restClient.Get().Namespace("default").Resource("pods").VersionedParams(&metav1.ListOptions{},
		scheme.ParameterCodec).Do(context.TODO()).Into(rest); err != nil {
		panic(err)
	}
	for _, v := range rest.Items {
		fmt.Printf("NameSpace: %v  Name: %v  Status: %v \n", v.Namespace, v.Name, v.Status.Phase)
	}
}

/*
结果
NameSpace: default  Name: nginx-76d6c9b8c-8ljkt  Status: Running 
NameSpace: default  Name: nginx-76d6c9b8c-jqv9h  Status: Running 
NameSpace: default  Name: nginx-76d6c9b8c-kr9d2  Status: Running 
NameSpace: default  Name: nginx-76d6c9b8c-m4g5l  Status: Running 
NameSpace: default  Name: nginx-76d6c9b8c-n8st9  Status: Running 
*/
```

### ClientSet

ClientSet是在RestClient的基础上封装了对资源和版本的管理方法。资源可以理解为一个客户端，而ClientSet是多个客户端的集合。在操作资源对象时，需要指定Group和Version，然后根据资源获取。然而，ClientSet不支持自定义资源定义（CRDs），但使用kubebuilder生成代码时，会生成相应的ClientSet。

```go
package main

import (
	"context"
	"fmt"
	"path/filepath"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func main() {
	ctx := context.Background()
	// 使用kubeconfig生成配置 ~/.kube/config
	config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
	if err != nil {
		panic(err)
	}
	// 生成clientSet
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}
	nodeList, err := clientSet.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	for _, node := range nodeList.Items {
		fmt.Printf("nodeName: %v, status: %v \n", node.GetName(), node.GetCreationTimestamp())
	}
  // pod 是有namespace资源所以指定namespace 而node没有
	pods, err := clientSet.CoreV1().Pods("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	for _, v := range pods.Items {
		fmt.Printf("namespace: %v podName: %v status: %v \n", v.Namespace, v.Name, v.Status.Phase)
	}
}

/*
结果:
nodeName: minikube, status: 2023-01-27 18:45:35 +0800 CST 
nodeName: minikube-m02, status: 2023-02-26 21:19:30 +0800 CST 
nodeName: minikube-m03, status: 2023-02-26 21:19:38 +0800 CST 
namespace: default podName: nginx-76d6c9b8c-8ljkt status: Running 
namespace: default podName: nginx-76d6c9b8c-jqv9h status: Running 
namespace: default podName: nginx-76d6c9b8c-kr9d2 status: Running 
namespace: default podName: nginx-76d6c9b8c-m4g5l status: Running 
namespace: default podName: nginx-76d6c9b8c-n8st9 status: Running 
*/
```

### DynamicClient

DynamicClient是一种动态客户端，它可以对任何资源进行RESTful操作，包括自定义资源定义（CRD）。与ClientSet不同，DynamicClient返回的对象是一个map[string]interface{}。如果一个控制器需要控制所有的API，可以使用DynamicClient。目前，DynamicClient在垃圾回收器和命名空间控制器中被广泛使用。

DynamicClient的处理过程将Resource（例如PodList）转换为unstructured类型。Kubernetes的所有资源都可以转换为这个结构类型。处理完毕后，再将其转换回PodList。整个转换过程类似于接口转换，即通过interface{}的断言实现。

DynamicClient是一种动态的客户端，它能处理Kubernetes所有的资源，但仅支持JSON

```go
package main

import (
	"context"
	"fmt"
	"path/filepath"

	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func main() {
	ctx := context.Background()
	// 使用kubeconfig生成配置 ~/.kube/config
	config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
	if err != nil {
		panic(err)
	}
	// dynamicClient
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		panic(err)
	}
	// 定义组版本资源
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	unStructObj, err := dynamicClient.Resource(gvr).Namespace("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	podList := &apiv1.PodList{}

	if err = runtime.DefaultUnstructuredConverter.FromUnstructured(unStructObj.UnstructuredContent(), podList); err != nil {
		panic(err)
	}

	for _, v := range podList.Items {
		fmt.Printf("namespaces:%v  podName:%v status:%v \n", v.Namespace, v.Name, v.Status.Phase)
	}
}

/*
namespaces:default  podName:nginx-76d6c9b8c-8ljkt status:Running
namespaces:default  podName:nginx-76d6c9b8c-jqv9h status:Running
namespaces:default  podName:nginx-76d6c9b8c-kr9d2 status:Running
namespaces:default  podName:nginx-76d6c9b8c-m4g5l status:Running
namespaces:default  podName:nginx-76d6c9b8c-n8st9 status:Running
*/
```

其中，GVR（group,version,resource） 用于标识 Kubernetes API 中的资源类型，其中 Group 表示 API 群组，Version 表示 API 版本，Resource 表示资源类型。例如，Deployment 的 GVR 为 "apps/v1/deployments"，其中 "apps" 是 API 群组，"v1" 是 API 版本，"deployments" 是资源类型。

### DiscoveryClient

DiscoveryClient 是一个发现客户端，它的主要作用是用于发现 API Server 支持的资源组、资源版本和资源信息。在 Kubernetes 中，API Server 支持很多资源组、资源版本和资源信息，我们可以通过使用 DiscoveryClient 来查看这些信息。此外，kubectl 的 API 版本和 API 资源也是通过 DiscoveryClient 来实现的。我们还可以将这些信息缓存到本地，以减轻 API 访问的压力。缓存文件默认存储在 `./kube/cache` 和 `./kube/http-cache` 目录下。

```go
package main

import (
	"fmt"
	"path/filepath"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func main() {
	// 使用kubeconfig生成配置 ~/.kube/config
	config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
	if err != nil {
		panic(err)
	}
	// 生成discoverClient
	discoverClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		panic(err)
	}
	_, apiResourceList, err := discoverClient.ServerGroupsAndResources()
	for _, v := range apiResourceList {
		gv, err := schema.ParseGroupVersion(v.GroupVersion)
		if err != nil {
			panic(err)
		}
		for _, resource := range v.APIResources {
			fmt.Printf("name:%v group:%v version:%v\n", resource.Name, gv.Group, gv.Version)
		}
	}
}

/*
name:bindings group: version:v1
name:componentstatuses group: version:v1
name:configmaps group: version:v1
name:endpoints group: version:v1
name:events group: version:v1
name:limitranges group: version:v1
name:namespaces group: version:v1
name:namespaces/finalize group: version:v1
name:namespaces/status group: version:v1
name:nodes group: version:v1
name:nodes/proxy group: version:v1
name:nodes/status group: version:v1
name:persistentvolumeclaims group: version:v1
name:persistentvolumeclaims/status group: version:v1
name:persistentvolumes group: version:v1
name:persistentvolumes/status group: version:v1
name:pods group: version:v1
name:pods/attach group: version:v1
name:pods/binding group: version:v1
name:pods/ephemeralcontainers group: version:v1
name:pods/eviction group: version:v1
name:pods/exec group: version:v1
name:pods/log group: version:v1
name:pods/portforward group: version:v1
name:pods/proxy group: version:v1
name:pods/status group: version:v1
name:podtemplates group: version:v1
name:replicationcontrollers group: version:v1
name:replicationcontrollers/scale group: version:v1
name:replicationcontrollers/status group: version:v1
name:resourcequotas group: version:v1
name:resourcequotas/status group: version:v1
name:secrets group: version:v1
name:serviceaccounts group: version:v1
name:serviceaccounts/token group: version:v1
name:services group: version:v1
name:services/proxy group: version:v1
name:services/status group: version:v1
name:apiservices group:apiregistration.k8s.io version:v1
name:apiservices/status group:apiregistration.k8s.io version:v1
name:controllerrevisions group:apps version:v1
name:daemonsets group:apps version:v1
name:daemonsets/status group:apps version:v1
name:deployments group:apps version:v1
name:deployments/scale group:apps version:v1
name:deployments/status group:apps version:v1
name:replicasets group:apps version:v1
name:replicasets/scale group:apps version:v1
name:replicasets/status group:apps version:v1
name:statefulsets group:apps version:v1
name:statefulsets/scale group:apps version:v1
name:statefulsets/status group:apps version:v1
name:events group:events.k8s.io version:v1
name:tokenreviews group:authentication.k8s.io version:v1
name:localsubjectaccessreviews group:authorization.k8s.io version:v1
name:selfsubjectaccessreviews group:authorization.k8s.io version:v1
name:selfsubjectrulesreviews group:authorization.k8s.io version:v1
name:subjectaccessreviews group:authorization.k8s.io version:v1
name:horizontalpodautoscalers group:autoscaling version:v2
name:horizontalpodautoscalers/status group:autoscaling version:v2
name:horizontalpodautoscalers group:autoscaling version:v1
name:horizontalpodautoscalers/status group:autoscaling version:v1
name:horizontalpodautoscalers group:autoscaling version:v2beta2
name:horizontalpodautoscalers/status group:autoscaling version:v2beta2
name:cronjobs group:batch version:v1
name:cronjobs/status group:batch version:v1
name:jobs group:batch version:v1
name:jobs/status group:batch version:v1
name:certificatesigningrequests group:certificates.k8s.io version:v1
name:certificatesigningrequests/approval group:certificates.k8s.io version:v1
name:certificatesigningrequests/status group:certificates.k8s.io version:v1
name:ingressclasses group:networking.k8s.io version:v1
name:ingresses group:networking.k8s.io version:v1
name:ingresses/status group:networking.k8s.io version:v1
name:networkpolicies group:networking.k8s.io version:v1
name:networkpolicies/status group:networking.k8s.io version:v1
name:poddisruptionbudgets group:policy version:v1
name:poddisruptionbudgets/status group:policy version:v1
name:clusterrolebindings group:rbac.authorization.k8s.io version:v1
name:clusterroles group:rbac.authorization.k8s.io version:v1
name:rolebindings group:rbac.authorization.k8s.io version:v1
name:roles group:rbac.authorization.k8s.io version:v1
name:csidrivers group:storage.k8s.io version:v1
name:csinodes group:storage.k8s.io version:v1
name:csistoragecapacities group:storage.k8s.io version:v1
name:storageclasses group:storage.k8s.io version:v1
name:volumeattachments group:storage.k8s.io version:v1
name:volumeattachments/status group:storage.k8s.io version:v1
name:csistoragecapacities group:storage.k8s.io version:v1beta1
name:mutatingwebhookconfigurations group:admissionregistration.k8s.io version:v1
name:validatingwebhookconfigurations group:admissionregistration.k8s.io version:v1
name:customresourcedefinitions group:apiextensions.k8s.io version:v1
name:customresourcedefinitions/status group:apiextensions.k8s.io version:v1
name:priorityclasses group:scheduling.k8s.io version:v1
name:leases group:coordination.k8s.io version:v1
name:runtimeclasses group:node.k8s.io version:v1
name:endpointslices group:discovery.k8s.io version:v1
name:flowschemas group:flowcontrol.apiserver.k8s.io version:v1beta2
name:flowschemas/status group:flowcontrol.apiserver.k8s.io version:v1beta2
name:prioritylevelconfigurations group:flowcontrol.apiserver.k8s.io version:v1beta2
name:prioritylevelconfigurations/status group:flowcontrol.apiserver.k8s.io version:v1beta2
name:flowschemas group:flowcontrol.apiserver.k8s.io version:v1beta1
name:flowschemas/status group:flowcontrol.apiserver.k8s.io version:v1beta1
name:prioritylevelconfigurations group:flowcontrol.apiserver.k8s.io version:v1beta1
name:prioritylevelconfigurations/status group:flowcontrol.apiserver.k8s.io version:v1beta1
name:nodes group:metrics.k8s.io version:v1beta1
name:pods group:metrics.k8s.io version:v1beta1
*/
```

## informer indexer  lister机制

![img](/images/client-go-controller-interaction-20230226221459038.jpeg)

上图展示了自定义控制器的工作方式。在虚线上方，是client-go包的informer和indexer工作方式。informer负责监听Kubernetes API资源对象的变化，如创建、更新、删除等操作，并将这些变化通知给indexer进行索引和缓存。而indexer则是将API对象进行索引，以便在需要时快速地访问它们。lister则是对indexer的封装，提供了一种简单的方式来获取已经索引的对象列表，以供代码中的其他部分使用。这种分层结构的设计使得client-go可以高效地处理Kubernetes资源对象的变化，并在应用程序中方便地使用这些资源对象。

### informer

Informer是Kubernetes API客户端中一种重要的机制，它可以实现对资源对象的监视和事件通知。当Kubernetes集群中的资源对象发生变化时，Informer可以及时地获取到这些变化，并将这些变化以事件的形式通知给相关的监听器。Informer通过调用API Server提供的REST接口，以及Kubernetes中定义的watch机制，实现了对集群资源对象的全面监视。

下面是一个简单的pod informer示例，用于监控所有pod的变化并将其放入队列中，worker从队列中取出pod并打印相关信息。

```go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/workqueue"
)

func main() {
	// 获取 kubeconfig 文件路径
	kubeconfigPath := os.Getenv("KUBECONFIG")
	if kubeconfigPath == "" {
		kubeconfigPath = os.Getenv("HOME") + "/.kube/config"
	}

	// 使用 kubeconfig 文件创建 kubernetes 客户端
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		panic(err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}

	// 创建 informer 工厂
	informerFactory := informers.NewSharedInformerFactory(clientset, time.Minute)

	// 创建 informer 对象
	podInformer := informerFactory.Core().V1().Pods()

	// 创建工作队列
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	// 定义处理新增、更新和删除事件的回调函数
	podHandler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err == nil {
				queue.Add(key)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(newObj)
			if err == nil {
				queue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err == nil {
				queue.Add(key)
			}
		},
	}

	// 将回调函数注册到 informer 上
	podInformer.Informer().AddEventHandler(podHandler)

	// 启动 informer
	stopCh := make(chan struct{})
	defer close(stopCh)
	informerFactory.Start(stopCh)

	// 等待 informer 同步完成
	if !cache.WaitForCacheSync(stopCh) {
		panic("同步 informer 缓存失败")
	}

	// 创建信号处理程序，用于捕捉 SIGTERM 和 SIGINT 信号
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGTERM, syscall.SIGINT)

	// 创建 worker 函数，用于处理队列中的事件
	processNextItem := func() {
		obj, shutdown := queue.Get()
		if shutdown {
			return
		}

		// 转换对象为 Pod
		key := obj.(string)
		podObj, exists, err := podInformer.Informer().GetIndexer().GetByKey(key)
		if err != nil {
			queue.Forget(obj)
			panic(fmt.Sprintf("获取 Pod 失败：%v", err))
		}

		if !exists {
			// 如果对象已经被删除，就把它从队列中移除
			queue.Forget(obj)
			return
		}

		// 在这里添加处理 Pod 的逻辑
		pod := podObj.(*v1.Pod)
		fmt.Printf("处理 Pod: namespace:%v,podName:%v\n", pod.Namespace, pod.Name)

		// 处理完事件后，把它从队列中移除
		queue.Forget(obj)
		return
	}

	// 启动 worker
	go wait.Until(processNextItem, time.Second, stopCh)

	// 等待信号
	<-signalCh
}

/*
处理 Pod: namespace:kube-system,podName:kindnet-h25kv
处理 Pod: namespace:kube-system,podName:kube-apiserver-minikube
处理 Pod: namespace:kube-system,podName:metrics-server-c9fb666df-zk4tb
处理 Pod: namespace:kubernetes-dashboard,podName:dashboard-metrics-scraper-b74747df5-4pb7w
处理 Pod: namespace:default,podName:nginx-76d6c9b8c-jqv9h
处理 Pod: namespace:default,podName:nginx-76d6c9b8c-m4g5l
处理 Pod: namespace:kube-system,podName:coredns-7f8cbcb969-48nz6
处理 Pod: namespace:kube-system,podName:kube-proxy-t766g
处理 Pod: namespace:kube-system,podName:kube-scheduler-minikube
处理 Pod: namespace:kube-system,podName:kindnet-44zl6
处理 Pod: namespace:kube-system,podName:kube-controller-manager-minikube
处理 Pod: namespace:kube-system,podName:kube-proxy-gq68w
处理 Pod: namespace:kube-system,podName:kube-proxy-l92vg
处理 Pod: namespace:kube-system,podName:storage-provisioner
处理 Pod: namespace:kubernetes-dashboard,podName:kubernetes-dashboard-57bbdc5f89-466rh
处理 Pod: namespace:default,podName:nginx-76d6c9b8c-kr9d2
处理 Pod: namespace:default,podName:nginx-76d6c9b8c-n8st9
处理 Pod: namespace:kube-system,podName:kindnet-w9f7t
处理 Pod: namespace:default,podName:nginx-76d6c9b8c-8ljkt
处理 Pod: namespace:kube-system,podName:etcd-minikube
处理 Pod: namespace:default,podName:nginx
处理 Pod: namespace:default,podName:ubuntu
*/
```

### indexer

Indexer是client-go中用于本地缓存资源对象的一种方式。它支持多种索引方式，并且可以使用函数`func(obj interface{}) ([]string, error)`进行索引。在检索时，需要使用相同的`indexName`参数。借助`informer`，indexer就可以维护一个特定资源的本地缓存，例如pod、namespace等。这种方法省去了每次get pod都要访问api-server的过程，从而减小了api-server的压力。

```go
// 如何使用索引器来检索Pod对象
package main

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	NamespaceIndexName = "namespace" // 定义一个索引器名称，用于按照命名空间检索Pod
	NodeNameIndexName  = "nodeName"  // 定义一个索引器名称，用于按照节点名称检索Pod
)

// NamespaceIndexFunc是一个函数，用于从对象中提取命名空间作为索引键
func NamespaceIndexFunc(obj interface{}) ([]string, error) {
	m, err := meta.Accessor(obj) // 获取对象的元数据
	if err != nil {
		return []string{""}, fmt.Errorf("object has no meta: %v", err)
	}
	return []string{m.GetNamespace()}, nil // 返回对象的命名空间
}

// NodeNameIndexFunc是一个函数，用于从Pod对象中提取节点名称作为索引键
func NodeNameIndexFunc(obj interface{}) ([]string, error) {
	pod, ok := obj.(*v1.Pod) // 判断对象是否是Pod类型
	if !ok {
		return []string{}, nil // 如果不是，返回空切片
	}
	return []string{pod.Spec.NodeName}, nil // 如果是，返回Pod的节点名称
}

func main() {
	index := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{
		NamespaceIndexName: NamespaceIndexFunc,
		NodeNameIndexName:  NodeNameIndexFunc,
	}) // 创建一个新的索引器，指定主键函数和辅助键函数

	pod1 := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "index-pod-1",
			Namespace: "default",
		},
		Spec: v1.PodSpec{NodeName: "node1"},
	} // 创建一个Pod对象，属于default命名空间和node1节点

	pod2 := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "index-pod-2",
			Namespace: "default",
		},
		Spec: v1.PodSpec{NodeName: "node2"},
	} // 创建另一个Pod对象，属于default命名空间和node2节点

	pod3 := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "index-pod-3",
			Namespace: "kube-system",
		},
		Spec: v1.PodSpec{NodeName: "node2"},
	} // 创建第三个Pod对象，属于kube-system命名空间和node2节点

	index.Add(pod1) // 将pod1添加到索引器中
	index.Add(pod2) // 将pod2添加到索引器中
	index.Add(pod3) // 将pod3添加到索引器中

	pods, err := index.ByIndex(NamespaceIndexName, "default") // 按照命名空间为default检索Pod列表
	if err != nil {
		panic(err)
	}
	for _, pod := range pods {
		fmt.Println(pod.(*v1.Pod).Name)
	} // 遍历并打印检索到的Pod名称

	fmt.Println("*****************")

	pods, err = index.ByIndex(NodeNameIndexName, "node2") // 按照节点名称为node2检索Pod列表
	if err != nil {
		panic(err)
	}
	for _, pod := range pods {
		fmt.Println(pod.(*v1.Pod).Name)
	} // 遍历并打印
}

/*
index-pod-2
index-pod-1
*****************
index-pod-2
index-pod-3
*/
```

### lister

Lister是对Indexer的封装，提供了一种方便的方式来获取已经索引的Kubernetes资源对象列表。

具体而言，Lister是一个接口，包含了获取所有已索引对象的列表以及根据名称获取单个对象的方法。这些方法可以帮助开发者在应用程序中快速访问已经缓存的资源对象，而无需直接与Indexer交互。

Lister的主要功能包括：

1. 提供方便的接口：Lister接口的方法定义清晰简洁，使用起来非常方便，可以快速地获取已经索引的资源对象列表。
2. 提高代码可读性：通过使用Lister接口，代码可读性得到提高。开发者可以更加专注于业务逻辑，而无需关注底层的Indexer实现细节。
3. 提高代码复用性：由于Lister接口已经提供了通用的方法，因此可以更容易地在不同的代码模块中重用相同的逻辑，减少代码重复。

总之，Lister作为client-go包中的一个重要组件，可以帮助开发者更加高效地处理Kubernetes资源对象，提高代码的可读性和可重用性。

```go
package main

import (
	"fmt"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	// 获取 kubeconfig 文件路径
	kubeconfigPath := os.Getenv("KUBECONFIG")
	if kubeconfigPath == "" {
		kubeconfigPath = os.Getenv("HOME") + "/.kube/config"
	}
	// 使用 kubeconfig 文件创建 kubernetes 客户端
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		panic(err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	// 创建Informer
	factory := informers.NewSharedInformerFactory(clientset, time.Minute)
	podInformer := factory.Core().V1().Pods()

	// 创建Lister
	lister := podInformer.Lister()

	// 等待Informer同步完成
	stopCh := make(chan struct{})
	defer close(stopCh)

	factory.Start(stopCh)
	cache.WaitForCacheSync(stopCh, podInformer.Informer().HasSynced)

	// 获取namespace为"default"的Pod对象
	podList, err := lister.Pods("default").List(labels.Everything())
	if err != nil {
		panic(err.Error())
	}
	// 打印Pod对象
	for _, pod := range podList {
		fmt.Printf("Pod name: %s, Namespace: %s\n", pod.Name, pod.Namespace)
	}
}

/*
Pod name: nginx-76d6c9b8c-m4g5l, Namespace: default
Pod name: nginx, Namespace: default
Pod name: ubuntu, Namespace: default
Pod name: nginx-76d6c9b8c-kr9d2, Namespace: default
Pod name: nginx-76d6c9b8c-n8st9, Namespace: default
Pod name: nginx-76d6c9b8c-8ljkt, Namespace: default
Pod name: nginx-76d6c9b8c-jqv9h, Namespace: default
*/
```

## Reference

- [sample-controller/controller-client-go.md at master · kubernetes/sample-controller (github.com)](https://github.com/kubernetes/sample-controller/blob/master/docs/controller-client-go.md)
- [K8s二开之 client-go 初探 - 掘金 (juejin.cn)](https://juejin.cn/post/6962869412785487909)
