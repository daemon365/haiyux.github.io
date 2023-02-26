---
title: "kubernetes client-go"
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

## indexer informer lister机制

![img](/images/client-go-controller-interaction-20230226221459038.jpeg)



## Reference

- [sample-controller/controller-client-go.md at master · kubernetes/sample-controller (github.com)](https://github.com/kubernetes/sample-controller/blob/master/docs/controller-client-go.md)
- [K8s二开之 client-go 初探 - 掘金 (juejin.cn)](https://juejin.cn/post/6962869412785487909)
