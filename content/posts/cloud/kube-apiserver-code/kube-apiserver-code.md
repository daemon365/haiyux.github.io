---
title: Kube Apiserver Code
subtitle:
date: 2023-05-16T21:54:37+08:00
draft: false
toc: true
categories: [cloud]
tags: [kubernetes]
authors:
    - haiyux
featuredImagePreview: /img/k8s.webp
---

## 简介

Kube-apiserver 是 Kubernetes 系统中的核心组件之一，它是 Kubernetes API 的前端组件，负责暴露 Kubernetes 集群的 API，并处理集群内外部的 API 请求。

以下是 kube-apiserver 的主要作用和功能：

1. API 暴露：kube-apiserver 为集群的各个组件（如 kube-controller-manager、kube-scheduler、kubelet 等）和用户提供了一个统一的入口点，通过 HTTP 或 HTTPS 协议暴露 Kubernetes API。其他组件和工具可以通过 kube-apiserver 与集群进行通信，执行各种操作。
2. 身份验证和授权：kube-apiserver 处理 API 请求时，会对请求进行身份验证和授权。它集成了各种身份验证机制，如基于令牌、客户端证书、用户名和密码等方式。在请求访问集群资源之前，kube-apiserver 会验证请求的身份和权限，确保只有经过授权的用户或组件才能执行相应操作。
3. 数据存储和持久化：kube-apiserver 通过与 etcd（外部键值存储系统）进行交互，将 Kubernetes 集群的各种资源配置信息（如 Pod、Service、ReplicaSet 等）持久化存储。它负责将 API 请求转换为 etcd 数据存储操作，并从 etcd 中检索数据以响应 API 请求。
4. 资源验证和默认值设置：kube-apiserver 对提交的资源配置进行验证，确保其符合 Kubernetes 的规范和限制。它会检查资源对象的结构、字段、标签等，并根据资源定义的默认值设置进行补充。这有助于保持集群中资源的一致性和正确性。
5. 请求处理和调度：kube-apiserver 接收 API 请求后，根据请求的类型和内容，将请求转发给相应的控制器或调度器进行处理。它协调集群内各个组件之间的交互，确保集群状态的一致性和可靠性。

kube-apiserver 是 Kubernetes 集群的 API 入口和核心处理组件，负责管理和维护集群的状态、配置和资源信息。通过与其他组件的交互，它实现了 Kubernetes 的核心功能，如资源管理、调度、扩展等。

## main

```go
func main() {
    // 创建一个cobra的command
	command := app.NewAPIServerCommand()
    // 启动
	code := cli.Run(command)
	os.Exit(code)
}
```

## NewAPIServerCommand

```GO
func NewAPIServerCommand() *cobra.Command {
    // 创建一个新的 ServerRunOptions 实例
    s := options.NewServerRunOptions()
    
    // 创建一个 cobra.Command 实例
    cmd := &cobra.Command{
        // 命令使用的名称
        Use: "kube-apiserver",
        
        // 命令的长描述信息
        Long: `The Kubernetes API server validates and configures data
for the api objects which include pods, services, replicationcontrollers, and
others. The API Server services REST operations and provides the frontend to the
cluster's shared state through which all other components interact.`,
        
        // 当命令发生错误时，停止打印用法信息
        SilenceUsage: true,
        
        // 在运行命令之前执行的持久性预运行函数
        PersistentPreRunE: func(*cobra.Command, []string) error {
            // 禁止 client-go 的警告输出
            // kube-apiserver 的 loopback 客户端不应该记录自己发出的警告
            rest.SetDefaultWarningHandler(rest.NoWarnings{})
            return nil
        },
        
        // 运行命令的函数
        RunE: func(cmd *cobra.Command, args []string) error {
            // 打印版本信息并在需要时退出
            verflag.PrintAndExitIfRequested()
            fs := cmd.Flags()
            
            // 在最早的时候激活日志记录，然后显示具有最终日志记录配置的标志。
            if err := logsapi.ValidateAndApply(s.Logs, utilfeature.DefaultFeatureGate); err != nil {
                return err
            }
            cliflag.PrintFlags(fs)
            
            // 设置默认选项
            completedOptions, err := Complete(s)
            if err != nil {
                return err
            }
            
            // 验证选项
            if errs := completedOptions.Validate(); len(errs) != 0 {
                return utilerrors.NewAggregate(errs)
            }
            
            // 添加功能启用度量信息
            utilfeature.DefaultMutableFeatureGate.AddMetrics()
            return Run(completedOptions, genericapiserver.SetupSignalHandler())
        },
        
        // 命令接受的参数验证函数
        Args: func(cmd *cobra.Command, args []string) error {
            for _, arg := range args {
                if len(arg) > 0 {
                    return fmt.Errorf("%q does not take any arguments, got %q", cmd.CommandPath(), args)
                }
            }
            return nil
        },
    }
    
    // 获取命令的标志
    fs := cmd.Flags()
    
    // 获取命名标志集合
    namedFlagSets := s.Flags()
    
    // 添加全局标志
    verflag.AddFlags(namedFlagSets.FlagSet("global"))
    globalflag.AddGlobalFlags(namedFlagSets.FlagSet("global"), cmd.Name(), logs.SkipLoggingConfigurationFlags())
    options.AddCustomGlobalFlags(namedFlagSets.FlagSet("generic"))
    for _, f := range namedFlagSets.FlagSets {
        fs.AddFlagSet(f)
    }
    
    // 获取终端的列数，并设置用法和帮助函数
    cols, _, _ := term.TerminalSize(cmd.OutOrStdout())
    cliflag.SetUsageAndHelpFunc(cmd, namedFlagSets, cols)
    
    return cmd
}
```

### ServerRunOptions

```go
type ServerRunOptions struct {
    // GenericServerRunOptions 定义了通用的服务器运行选项
    GenericServerRunOptions *genericoptions.ServerRunOptions
    
    // Etcd 定义了与 Etcd 相关的选项
    Etcd *genericoptions.EtcdOptions
    
    // SecureServing 定义了与安全服务相关的选项，包括循环回环
    SecureServing *genericoptions.SecureServingOptionsWithLoopback
    
    // Audit 定义了与审计相关的选项
    Audit *genericoptions.AuditOptions
    
    // Features 定义了与功能相关的选项
    Features *genericoptions.FeatureOptions
    
    // Admission 定义了与准入控制相关的选项
    Admission *kubeoptions.AdmissionOptions
    
    // Authentication 定义了与认证相关的选项
    Authentication *kubeoptions.BuiltInAuthenticationOptions
    
    // Authorization 定义了与授权相关的选项
    Authorization *kubeoptions.BuiltInAuthorizationOptions
    
    // CloudProvider 定义了与云提供商相关的选项
    CloudProvider *kubeoptions.CloudProviderOptions
    
    // APIEnablement 定义了与 API 启用相关的选项
    APIEnablement *genericoptions.APIEnablementOptions
    
    // EgressSelector 定义了与出口选择器相关的选项
    EgressSelector *genericoptions.EgressSelectorOptions
    
    // Metrics 定义了与指标相关的选项
    Metrics *metrics.Options
    
    // Logs 定义了与日志相关的选项
    Logs *logs.Options
    
    // Traces 定义了与跟踪相关的选项
    Traces *genericoptions.TracingOptions
    
    AllowPrivileged           bool
    EnableLogsHandler         bool
    EventTTL                  time.Duration
    KubeletConfig             kubeletclient.KubeletClientConfig
    KubernetesServiceNodePort int
    
    // MaxConnectionBytesPerSec 定义了每秒的最大连接字节数
    MaxConnectionBytesPerSec int64
    
    // ServiceClusterIPRange 是用户提供的输入，映射到实际值
    ServiceClusterIPRanges string
    
    // PrimaryServiceClusterIPRange 和 SecondaryServiceClusterIPRange 是将 ServiceClusterIPRange 解析为实际值的结果
    PrimaryServiceClusterIPRange   net.IPNet
    SecondaryServiceClusterIPRange net.IPNet
    
    // APIServerServiceIP 是 PrimaryServiceClusterIPRange 中的第一个有效 IP
    APIServerServiceIP net.IP
    // 定义了服务节点端口范围，用于分配给NodePort类型的服务的端口号
    ServiceNodePortRange utilnet.PortRange
    	
    // 定义了用于代理客户端的证书文件路径和密钥文件路径
    ProxyClientCertFile string
    ProxyClientKeyFile  string
    
    // 是否启用聚合器路由功能，用于将请求路由到聚合器
    EnableAggregatorRouting             bool
    // 聚合器是否拒绝转发重定向请求
    AggregatorRejectForwardingRedirects bool
    
    // 主节点的数量，用于高可用部署中的主节点选举
    MasterCount            int
    // 指定了端点协调器的类型，用于处理集群中服务和端点的变化
    EndpointReconcilerType string
    
    // 定义了用于签署服务账户令牌的密钥文件路径
    ServiceAccountSigningKeyFile     string
    // 定义了服务账户令牌的发行者，用于生成和验证令牌
    ServiceAccountIssuer             serviceaccount.TokenGenerator
    // 定义了服务账户令牌的最大有效期
    ServiceAccountTokenMaxExpiration time.Duration
    // 隐藏的指标在指定版本中是否可见
    ShowHiddenMetricsForVersion string
}

func NewServerRunOptions() *ServerRunOptions {
	s := ServerRunOptions{
		// 创建一些默认值
	}

	return &s
}

// 使用flag绑定参数
func (s *ServerRunOptions) Flags() (fss cliflag.NamedFlagSets) {
	s.GenericServerRunOptions.AddUniversalFlags(fss.FlagSet("generic"))
    // ...
	return fss
}
```

## Run

```go
// Run函数运行指定的APIServer。该函数应该永不退出。
func Run(completeOptions completedServerRunOptions, stopCh <-chan struct{}) error {
    // 为了帮助调试，立即记录版本号
    klog.Infof("Version: %+v", version.Get())
    // 记录Golang的一些设置，用于调试
    klog.InfoS("Golang settings", "GOGC", os.Getenv("GOGC"), "GOMAXPROCS", os.Getenv("GOMAXPROCS"), "GOTRACEBACK", os.Getenv("GOTRACEBACK"))

    // 创建一个server，并返回错误信息，如果有的话
    server, err := CreateServerChain(completeOptions)
    if err != nil {
        return err
    }

    // 准备运行server，并返回错误信息，如果有的话
    prepared, err := server.PrepareRun()
    if err != nil {
        return err
    }

    // 运行server，返回结果
    return prepared.Run(stopCh)
}
```

## CreateServerChain

```go
// CreateServerChain函数创建通过委托连接的API服务器。
func CreateServerChain(completedOptions completedServerRunOptions) (*aggregatorapiserver.APIAggregator, error) {
    // 创建kubeAPIServerConfig、serviceResolver、pluginInitializer和错误信息err
    kubeAPIServerConfig, serviceResolver, pluginInitializer, err := CreateKubeAPIServerConfig(completedOptions)
    if err != nil {
    	return nil, err
    }
    // 如果添加了其他API服务器，则应该进行检查
    apiExtensionsConfig, err := createAPIExtensionsConfig(*kubeAPIServerConfig.GenericConfig, kubeAPIServerConfig.ExtraConfig.VersionedInformers, pluginInitializer, completedOptions.ServerRunOptions, completedOptions.MasterCount,
        serviceResolver, webhook.NewDefaultAuthenticationInfoResolverWrapper(kubeAPIServerConfig.ExtraConfig.ProxyTransport, kubeAPIServerConfig.GenericConfig.EgressSelector, kubeAPIServerConfig.GenericConfig.LoopbackClientConfig, kubeAPIServerConfig.GenericConfig.TracerProvider))
    if err != nil {
        return nil, err
    }

    // 创建notFoundHandler，并使用它创建apiExtensionsServer
    notFoundHandler := notfoundhandler.New(kubeAPIServerConfig.GenericConfig.Serializer, genericapifilters.NoMuxAndDiscoveryIncompleteKey)
    apiExtensionsServer, err := createAPIExtensionsServer(apiExtensionsConfig, genericapiserver.NewEmptyDelegateWithCustomHandler(notFoundHandler))
    if err != nil {
        return nil, err
    }

    // 创建kubeAPIServer
    kubeAPIServer, err := CreateKubeAPIServer(kubeAPIServerConfig, apiExtensionsServer.GenericAPIServer)
    if err != nil {
        return nil, err
    }

    // 最后创建aggregatorConfig，并使用它创建aggregatorServer
    aggregatorConfig, err := createAggregatorConfig(*kubeAPIServerConfig.GenericConfig, completedOptions.ServerRunOptions, kubeAPIServerConfig.ExtraConfig.VersionedInformers, serviceResolver, kubeAPIServerConfig.ExtraConfig.ProxyTransport, pluginInitializer)
    if err != nil {
        return nil, err
    }
    aggregatorServer, err := createAggregatorServer(aggregatorConfig, kubeAPIServer.GenericAPIServer, apiExtensionsServer.Informers)
    if err != nil {
        // 因为aggregator服务器不创建任何goroutine，所以我们不需要特殊处理innerStopCh
        return nil, err
    }

    return aggregatorServer, nil
}
```

### CreateKubeAPIServerConfig


```go
// CreateKubeAPIServerConfig函数创建运行API服务器所需的所有资源，但不运行它们。
func CreateKubeAPIServerConfig(s completedServerRunOptions) (
    *controlplane.Config,
    aggregatorapiserver.ServiceResolver,
    []admission.PluginInitializer,
    error,
) {
    // 创建代理传输配置
    proxyTransport := CreateProxyTransport()
    // 构建通用配置、版本化Informers、serviceResolver、pluginInitializers、admissionPostStartHook和storageFactory
    genericConfig, versionedInformers, serviceResolver, pluginInitializers, admissionPostStartHook, storageFactory, err := buildGenericConfig(s.ServerRunOptions, proxyTransport)
    if err != nil {
        return nil, nil, nil, err
    }

    // 设置capabilities
    capabilities.Setup(s.AllowPrivileged, s.MaxConnectionBytesPerSec)

    // 应用度量信息
    s.Metrics.Apply()
    serviceaccount.RegisterMetrics()

    // 创建配置对象
    config := &controlplane.Config{
        GenericConfig: genericConfig,
        ExtraConfig: controlplane.ExtraConfig{
            APIResourceConfigSource: storageFactory.APIResourceConfigSource,
            StorageFactory:          storageFactory,
            EventTTL:                s.EventTTL,
            KubeletClientConfig:     s.KubeletConfig,
            EnableLogsSupport:       s.EnableLogsHandler,
            ProxyTransport:          proxyTransport,

            ServiceIPRange:          s.PrimaryServiceClusterIPRange,
            APIServerServiceIP:      s.APIServerServiceIP,
            SecondaryServiceIPRange: s.SecondaryServiceClusterIPRange,

            APIServerServicePort: 443,

            ServiceNodePortRange:      s.ServiceNodePortRange,
            KubernetesServiceNodePort: s.KubernetesServiceNodePort,

            EndpointReconcilerType: reconcilers.Type(s.EndpointReconcilerType),
            MasterCount:            s.MasterCount,

            ServiceAccountIssuer:        s.ServiceAccountIssuer,
            ServiceAccountMaxExpiration: s.ServiceAccountTokenMaxExpiration,
            ExtendExpiration:            s.Authentication.ServiceAccounts.ExtendExpiration,

            VersionedInformers: versionedInformers,
        },
    }

    // 获取客户端证书的CA提供者
    clientCAProvider, err := s.Authentication.ClientCert.GetClientCAContentProvider()
    if err != nil {
        return nil, nil, nil, err
    }
    config.ExtraConfig.ClusterAuthenticationInfo.ClientCA = clientCAProvider

    // 获取请求头认证配置
    requestHeaderConfig, err := s.Authentication.RequestHeader.ToAuthenticationRequestHeaderConfig()
    if err != nil {
        return nil, nil, nil, err
    }
    if requestHeaderConfig != nil {
        config.ExtraConfig.ClusterAuthenticationInfo.RequestHeaderCA = requestHeaderConfig.CAContentProvider
        config.ExtraConfig.ClusterAuthenticationInfo.RequestHeaderAllowedNames = requestHeaderConfig.AllowedClientNames
        config.ExtraConfig.ClusterAuthenticationInfo.RequestHeaderExtraHeaderPrefixes = requestHeaderConfig.ExtraHeaderPrefixes
        config.ExtraConfig.ClusterAuthenticationInfo.RequestHeaderGroupHeaders = requestHeaderConfig.GroupHeaders
        config.ExtraConfig.ClusterAuthenticationInfo.RequestHeaderUsernameHeaders = requestHeaderConfig.UsernameHeaders
    }

    // 添加admissionPostStartHook到GenericConfig的PostStartHooks中
    if err := config.GenericConfig.AddPostStartHook("start-kube-apiserver-admission-initializer", admissionPostStartHook); err != nil {
        return nil, nil, nil, err
    }

    if config.GenericConfig.EgressSelector != nil {
		// 使用config.GenericConfig.EgressSelector查找用于连接到kubelet的拨号器
		config.ExtraConfig.KubeletClientConfig.Lookup = config.GenericConfig.EgressSelector.Lookup

		// 使用config.GenericConfig.EgressSelector查找作为"proxy"子资源使用的传输
		networkContext := egressselector.Cluster.AsNetworkContext()
		dialer, err := config.GenericConfig.EgressSelector.Lookup(networkContext)
		if err != nil {
			return nil, nil, nil, err
		}
		c := proxyTransport.Clone()
		c.DialContext = dialer
		config.ExtraConfig.ProxyTransport = c
	}

	// 加载公钥
	var pubKeys []interface{}
	for _, f := range s.Authentication.ServiceAccounts.KeyFiles {
		keys, err := keyutil.PublicKeysFromFile(f)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse key file %q: %v", f, err)
		}
		pubKeys = append(pubKeys, keys...)
	}
	// 通过ExtraConfig传递所需的元数据
	config.ExtraConfig.ServiceAccountIssuerURL = s.Authentication.ServiceAccounts.Issuers[0]
	config.ExtraConfig.ServiceAccountJWKSURI = s.Authentication.ServiceAccounts.JWKSURI
	config.ExtraConfig.ServiceAccountPublicKeys = pubKeys

	return config, serviceResolver, pluginInitializers, nil
}
```

```GO
// ServiceResolver是一个根据服务获取URL的解析器接口。
type ServiceResolver interface {
	ResolveEndpoint(namespace, name string, port int32) (*url.URL, error)
}

// PluginInitializer用于初始化入场插件之间共享的资源。
// 初始化后，需要单独设置这些资源。
type PluginInitializer interface {
	Initialize(plugin Interface)
}

// Config定义了主控节点的配置。
type Config struct {
    GenericConfig *genericapiserver.Config
    ExtraConfig ExtraConfig
}

// Config是用于配置GenericAPIServer的结构体。
// 其成员按照大致重要性的顺序进行排序。
type Config struct {
    // SecureServing用于提供HTTPS服务
    SecureServing *SecureServingInfo
	// Authentication是用于认证的配置
    Authentication AuthenticationInfo

    // Authorization是用于授权的配置
    Authorization AuthorizationInfo

    // LoopbackClientConfig是一个用于与API服务器建立特权环回连接的配置。
    // 这对于GenericAPIServer上的PostStartHooks的正确功能是必需的。
    // TODO：尽快将其移动到SecureServing（WithLoopback）中，一旦不再支持不安全的服务。
    LoopbackClientConfig *restclient.Config

    // EgressSelector根据在启动时读取的EgressSelectorConfiguration提供的信息，提供查找机制以进行外部连接。
    EgressSelector *egressselector.EgressSelector

    // RuleResolver用于获取适用于给定用户和命名空间的规则列表。
    RuleResolver authorizer.RuleResolver
    // AdmissionControl用于对给定的请求（包括内容）进行深入检查，以设置值并确定是否允许该请求。
    AdmissionControl admission.Interface
    CorsAllowedOriginList []string
    HSTSDirectives        []string
    // FlowControl（如果非nil）将优先级和公平性应用于请求处理
    FlowControl utilflowcontrol.Interface

    EnableIndex     bool
    EnableProfiling bool
    DebugSocketPath string
    EnableDiscovery bool

    // 需要启用通用分析
    EnableContentionProfiling bool
    EnableMetrics             bool

    DisabledPostStartHooks sets.String
    // 此映射中的值会被忽略。
    PostStartHooks map[string]PostStartHookConfigEntry

    // 如果非nil，Version将启用/version端点。
    Version *version.Info
    // AuditBackend用于发送审计事件。
    AuditBackend audit.Backend
    // AuditPolicyRuleEvaluator用于决定是否以及如何记录请求的审计日志。
    AuditPolicyRuleEvaluator audit.PolicyRuleEvaluator
    // ExternalAddress是用于外部（公共互联网）面向URL（例如Swagger）的主机名。
    // 将默认值设置为基于SecureServing信息和可用的IPv4地址的值。
    ExternalAddress string

    // TracerProvider可以提供一个跟踪器，用于记录分布式跟踪的跨度。
    TracerProvider tracing.TracerProvider

    //===========================================================================
    // 以下字段可能不太需要更改
    //===========================================================================

    // BuildHandlerChainFunc允许您通过装饰apiHandler来构建自定义处理程序链。
    BuildHandlerChainFunc func(apiHandler http.Handler, c *Config) (secure http.Handler)
    // NonLongRunningRequestWaitGroup允许您在服务器关闭时等待与非长时间运行请求相关的所有处理程序完成。
    NonLongRunningRequestWaitGroup *utilwaitgroup.SafeWaitGroup
    // WatchRequestWaitGroup允许我们在服务器关闭时等待与活动监视请求相关的所有处理程序完成。
    WatchRequestWaitGroup *utilwaitgroup.RateLimitedSafeWaitGroup
    // DiscoveryAddresses用于构建传递给discovery的IP地址。如果为nil，则始终报告ExternalAddress。
    DiscoveryAddresses discovery.Addresses
    // 默认的健康检查集合。可以通过AddHealthChecks动态添加更多。
    HealthzChecks []healthz.HealthChecker
	// 默认的livez检查集合。可以通过AddHealthChecks动态添加更多。
    LivezChecks []healthz.HealthChecker
    // 默认的readyz-only检查集合。可以通过AddReadyzChecks动态添加更多。
    ReadyzChecks []healthz.HealthChecker
    // LegacyAPIGroupPrefixes用于设置授权和验证请求的URL解析。新的API服务器通常根本没有传统组。
    LegacyAPIGroupPrefixes sets.String
    // RequestInfoResolver用于根据请求URL分配属性（用于admission和authorization）。
    // 像kubelets这样的用例可能需要自定义此功能。
    RequestInfoResolver apirequest.RequestInfoResolver
    // Serializer是必需的，并提供序列化和转换对象的接口。
    // 默认值（api.Codecs）通常可以正常工作。
    Serializer runtime.NegotiatedSerializer
    // OpenAPIConfig将用于生成OpenAPI规范。默认为nil。使用DefaultOpenAPIConfig获取“工作”默认值。
    OpenAPIConfig *openapicommon.Config
    // OpenAPIV3Config将用于生成OpenAPI V3规范。默认为nil。使用DefaultOpenAPIV3Config获取“工作”默认值。
    OpenAPIV3Config *openapicommon.Config
    // SkipOpenAPIInstallation如果设置为true，则避免安装OpenAPI处理程序。
    SkipOpenAPIInstallation bool
    // RESTOptionsGetter用于通过通用注册表构造RESTStorage类型。
    RESTOptionsGetter genericregistry.RESTOptionsGetter
    // 如果指定，除符合LongRunningFunc谓词的请求外，所有请求都将在此持续时间后超时。
    // 0表示没有限制。
    RequestTimeout time.Duration
    // 如果指定，诸如watch之类的长时间运行请求将分配一个在此值和两倍此值之间的随机超时时间。
    // 请注意，请求处理程序需要忽略或遵守此超时时间。以秒为单位。
    MinRequestTimeout int
    // 这表示apiserver完成启动序列并变为健康状态所需的最长时间。
    // 从apiserver的启动时间开始计算，直到经过此时间为止，/livez将假设未完成的post-start hook将成功完成，并因此返回true。
    LivezGracePeriod time.Duration
    // ShutdownDelayDuration允许阻塞关闭一段时间，例如直到指向此API服务器的端点在所有节点上收敛。
    // 在此期间，API服务器将继续提供服务，/healthz将返回200，但/readyz将返回失败。
    ShutdownDelayDuration time.Duration
    // MaxRequestBodyBytes是将在写请求中接受和解码的请求大小限制。
    // 0表示没有限制。
    MaxRequestBodyBytes int64
    // MaxRequestsInFlight是非长时间运行请求的最大并行数量。
    // 每个进一步的请求都必须等待。仅适用于非突变请求。
    MaxRequestsInFlight int
    // MaxMutatingRequestsInFlight是并行突变请求的最大数量。
    // 每个进一步的请求都必须等待。
    MaxMutatingRequestsInFlight int
     // LongRunningFunc是一个谓词，对于长时间运行的HTTP请求的路径为true。
    LongRunningFunc apirequest.LongRunningRequestCheck
   
    GoawayChance float64
    // GoawayChance是发送GOAWAY给HTTP/2客户端的概率。
    // 当客户端收到GOAWAY时，正在处理的请求不受影响，并且新请求将使用新的TCP连接触发负载平衡到其他服务器。
    // 默认值为0，表示永不发送GOAWAY。最大值为0.02，以防止破坏apiserver。

    MergedResourceConfig *serverstore.ResourceConfig
    // MergedResourceConfig指示哪个groupVersion启用，以及其资源启用/禁用的信息。
    // 这由genericapiserver的defaultAPIResourceConfig组成，并从标志解析的那些组合而成。
    // 如果在标志中未指定任何内容，则genericapiserver将仅启用defaultAPIResourceConfig。

    lifecycleSignals lifecycleSignals
    // lifecycleSignals提供对apiserver生命周期中发生的各种信号的访问。
    // 它有意标记为私有，因为它不应被覆盖。

    StorageObjectCountTracker flowcontrolrequest.StorageObjectCountTracker
    // StorageObjectCountTracker用于跟踪存储中每个资源的对象总数，
    // 以便我们可以估计传入请求的宽度。

    ShutdownSendRetryAfter bool
    // ShutdownSendRetryAfter规定何时在apiserver的优雅终止期间启动HTTP Server的关闭。
    // 如果为true，我们等待正在进行的非长时间运行的请求完成，然后启动HTTP Server的关闭。
    // 如果为false，我们在ShutdownDelayDuration经过后启动HTTP Server的关闭。
    // 如果启用，则在ShutdownDelayDuration经过后，任何传入请求都将以429状态码拒绝并返回'Retry-After'响应。

    //===========================================================================
    // 下面的值是待删除的目标
    //===========================================================================

    PublicAddress net.IP
    // PublicAddress是集群成员（kubelet、kube-proxy、服务等）可以访问GenericAPIServer的IP地址。
    // 如果为nil或0.0.0.0，则使用主机的默认接口。

    EquivalentResourceRegistry runtime.EquivalentResourceRegistry
    // EquivalentResourceRegistry提供与给定资源等效的资源信息，
    // 以及与给定资源关联的kind。随着资源的安装，它们在此处注册。
    
    APIServerID string
   	// APIServerID是此API服务器的ID
    
    // StorageVersionManager持有此服务器安装的API资源的存储版本。
    StorageVersionManager storageversion.Manager

    // Version如果非空，则启用/version端点。
    Version *version.Info

    // lifecycleSignals提供对API服务器生命周期中发生的各种信号的访问。
    lifecycleSignals lifecycleSignals

    // destroyFns包含在关闭时应调用以清理资源的函数列表。
    destroyFns []func()

    // muxAndDiscoveryCompleteSignals保存指示所有已知HTTP路径已注册的信号。
    // 它主要用于避免在资源实际存在但我们未安装到处理程序的路径时返回404响应。
    // 它暴露出来以更轻松地组合各个服务器。
    // 此字段的主要使用者是WithMuxCompleteProtection过滤器和NotFoundHandler。
    muxAndDiscoveryCompleteSignals map[string]<-chan struct{}

    // ShutdownSendRetryAfter决定在API服务器的优雅终止期间何时启动HTTP服务器的关闭。
    // 如果为true，则等待非长时间运行的请求完成后再启动HTTP服务器的关闭。
    // 如果为false，则在ShutdownDelayDuration经过后立即启动HTTP服务器的关闭。
    // 如果启用，在ShutdownDelayDuration经过后，任何传入的请求都将以429状态码和'Retry-After'响应被拒绝。
    ShutdownSendRetryAfter bool

    // ShutdownWatchTerminationGracePeriod如果设置为正值，则是API服务器等待所有活动的观察请求完成的最大持续时间。
    // 一旦此优雅期限结束，API服务器将不再等待任何活动的观察请求完成，它将继续执行优雅服务器关闭过程的下一步。
    // 如果设置为正值，API服务器将跟踪正在进行的观察请求的数量，并在关闭期间等待最长指定的持续时间，并允许这些活动的观察请求在生效的速率限制下完成。
    // 默认值为零，这意味着API服务器不会跟踪活动的观察请求并且不会等待它们完成，这保持了向后兼容性。
    // 此优雅期限与其他优雅期限无关，并且不受其他任何优雅期限的覆盖。
    ShutdownWatchTerminationGracePeriod time.Duration
}

// ExtraConfig定义了主控节点的额外配置信息
type ExtraConfig struct {
	ClusterAuthenticationInfo clusterauthenticationtrust.ClusterAuthenticationInfo // 集群认证信息
    APIResourceConfigSource  serverstorage.APIResourceConfigSource // API资源配置源
    StorageFactory           serverstorage.StorageFactory          // 存储工厂
    EndpointReconcilerConfig EndpointReconcilerConfig             // 终结点调和器配置
    EventTTL                 time.Duration                        // 事件的生存时间
    KubeletClientConfig      kubeletclient.KubeletClientConfig     // Kubelet客户端配置

    EnableLogsSupport bool              // 是否启用日志支持
    ProxyTransport    *http.Transport   // 代理传输配置

    // 用于构建发现中使用的IP地址的值
    // 分配给类型为ClusterIP或更大的服务的IP范围
    ServiceIPRange net.IPNet // 服务IP范围
    // 用于GenericAPIServer服务的IP地址（必须在ServiceIPRange内）
    APIServerServiceIP net.IP // GenericAPIServer服务的IP地址

    // 双栈服务，该范围表示服务IP的备用IP范围
    // 必须与主要的（ServiceIPRange）的地址族不同
    SecondaryServiceIPRange net.IPNet // 备用服务IP范围
    // 用于GenericAPIServer服务的备用IP地址（必须在SecondaryServiceIPRange内）
    SecondaryAPIServerServiceIP net.IP // GenericAPIServer服务的备用IP地址

    // apiserver服务的端口。
    APIServerServicePort int // apiserver服务的端口

    // TODO，可能可以将服务相关的项目分组到一个子结构中，以便更容易配置
    // API server项目和“Extra*”字段可能很好地配合在一起。

    // 分配给类型为NodePort或更大的服务的端口范围
    ServiceNodePortRange utilnet.PortRange // 服务NodePort范围
    // 如果非零，"kubernetes"服务将使用此端口作为NodePort。
    KubernetesServiceNodePort int // kubernetes服务的NodePort端口

    // 运行的主控节点数；所有主控节点必须以相同的值启动。 （未经测试的数字> 1。）
    MasterCount int // 主控节点数

    // MasterEndpointReconcileTTL设置每个主控节点记录的终结点记录的生存时间（以秒为单位）。
    // 终结点将以每个节点设置的2/3间隔进行检查，并且如果未设置此值，则该值默认为15秒。
    // 在非常大的集群中，可以增加此值以减少主控节点终结点记录过期（由于etcd服务器上的其他负载）并导致主控节点在kubernetes服务记录中出现和消失的可能性。
    // 不建议将此值设置为小于15秒。
    MasterEndpointReconcileTTL time.Duration // 主控节点终结点记录的生存时间

    EndpointReconcilerType reconcilers.Type // 选择要使用的调和器类型

    ServiceAccountIssuer serviceaccount.TokenGenerator // ServiceAccount签发者
    ServiceAccountMaxExpiration time.Duration // ServiceAccount的最大过期时间
    ExtendExpiration bool // 是否延长过期时间

    // ServiceAccountIssuerDiscovery
    ServiceAccountIssuerURL string // ServiceAccount签发者的URL
    ServiceAccountJWKSURI string // ServiceAccount的JWKS URI
    ServiceAccountPublicKeys []interface{} // ServiceAccount的公钥

    VersionedInformers informers.SharedInformerFactory // 版本化Informers共享的工厂

    // RepairServicesInterval用于修复循环的时间间隔
    // 用于修复Services NodePort和ClusterIP资源
    RepairServicesInterval time.Duration // 修复服务的时间间隔
}
```

### NewDefaultAuthenticationInfoResolverWrapper

```go
// NewDefaultAuthenticationInfoResolverWrapper 构建默认的身份验证解析器包装器
func NewDefaultAuthenticationInfoResolverWrapper(
	proxyTransport *http.Transport,
	egressSelector *egressselector.EgressSelector,
	kubeapiserverClientConfig *rest.Config,
	tp trace.TracerProvider) AuthenticationInfoResolverWrapper {

	// webhookAuthResolverWrapper 是一个函数，接受一个 AuthenticationInfoResolver 参数并返回一个 AuthenticationInfoResolver
	webhookAuthResolverWrapper := func(delegate AuthenticationInfoResolver) AuthenticationInfoResolver {
		return &AuthenticationInfoResolverDelegator{
			ClientConfigForFunc: func(hostPort string) (*rest.Config, error) {
				// 如果 hostPort 是 "kubernetes.default.svc:443"，则返回 kubeapiserverClientConfig 和 nil
				if hostPort == "kubernetes.default.svc:443" {
					return kubeapiserverClientConfig, nil
				}
				// 否则调用 delegate 的 ClientConfigFor 方法获取 rest.Config
				ret, err := delegate.ClientConfigFor(hostPort)
				if err != nil {
					return nil, err
				}
				// 如果启用了 features.APIServerTracing 特性，则在返回的 rest.Config 上执行 ret.Wrap(tracing.WrapperFor(tp))
				if feature.DefaultFeatureGate.Enabled(features.APIServerTracing) {
					ret.Wrap(tracing.WrapperFor(tp))
				}

				// 如果 egressSelector 不为 nil，则执行以下代码块
				if egressSelector != nil {
					// 将 egressselector.ControlPlane 转换为 NetworkContext，并存储在 networkContext 变量中
					networkContext := egressselector.ControlPlane.AsNetworkContext()
					var egressDialer utilnet.DialFunc
					// 通过 egressSelector.Lookup 查找对应的 egressDialer
					egressDialer, err = egressSelector.Lookup(networkContext)

					if err != nil {
						return nil, err
					}

					// 将返回的 egressDialer 赋值给 ret.Dial
					ret.Dial = egressDialer
				}
				return ret, nil
			},
			ClientConfigForServiceFunc: func(serviceName, serviceNamespace string, servicePort int) (*rest.Config, error) {
				// 如果 serviceName 是 "kubernetes"，serviceNamespace 是 corev1.NamespaceDefault，servicePort 是 443，则返回 kubeapiserverClientConfig 和 nil
				if serviceName == "kubernetes" && serviceNamespace == corev1.NamespaceDefault && servicePort == 443 {
					return kubeapiserverClientConfig, nil
				}
				// 否则调用 delegate 的 ClientConfigForService 方法获取 rest.Config
				ret, err := delegate.ClientConfigForService(serviceName, serviceNamespace, servicePort)
				if err != nil {
					return nil, err
				}
				// 如果启用了 features.APIServerTracing 特性，则在返回的 rest.Config 上执行 ret.Wrap(tracing.WrapperFor(tp))
				if feature.DefaultFeatureGate.Enabled(features.APIServerTracing) {
					ret.Wrap(tracing.WrapperFor(tp))
				}

				// 如果 egressSelector 不为 nil，则执行以下代码块
				if egressSelector != nil {
					// 将 egressselector.Cluster 转换为 NetworkContext，并存储在 networkContext 变量中
					networkContext := egressselector.Cluster.AsNetworkContext()
					var egressDialer utilnet.DialFunc
                    // 通过 egressSelector.Lookup 查找对应的 egressDialer
					egressDialer, err = egressSelector.Lookup(networkContext)
					if err != nil {
						return nil, err
					}
					// 将返回的 egressDialer 赋值给 ret.Dial
					ret.Dial = egressDialer
				} else if proxyTransport != nil && proxyTransport.DialContext != nil {
                    // 如果 proxyTransport 不为 nil，并且 proxyTransport.DialContext 不为 nil，则将 proxyTransport.DialContext 赋值给 ret.Dial
					ret.Dial = proxyTransport.DialContext
				}
				return ret, nil
			},
		}
	}
    // 返回 webhookAuthResolverWrapper 函数
	return webhookAuthResolverWrapper
}
```

### createAPIExtensionsConfig

```go
func createAPIExtensionsConfig(
    kubeAPIServerConfig genericapiserver.Config, // kube-apiserver的通用配置
    externalInformers kubeexternalinformers.SharedInformerFactory, // 外部Informers的共享工厂
    pluginInitializers []admission.PluginInitializer, // 插件初始化器列表
    commandOptions *options.ServerRunOptions, // 服务器运行选项
    masterCount int, // 主控节点数
    serviceResolver webhook.ServiceResolver, // webhook服务解析器
    authResolverWrapper webhook.AuthenticationInfoResolverWrapper, // webhook身份验证信息解析器包装器
) (*apiextensionsapiserver.Config, error) {
    // 创建通用配置的浅层副本，以便进行一些调整
    // 大部分配置实际上保持不变。我们只需要修改与apiextensions的特定内容相关的一些项目
    genericConfig := kubeAPIServerConfig
    genericConfig.PostStartHooks = map[string]genericapiserver.PostStartHookConfigEntry{}
    genericConfig.RESTOptionsGetter = nil
	// 复制etcd选项，以免改变原始值。
    // 我们假设etcd选项已经完成。避免对StorageConfig之外的任何内容进行更改，以免在应用选项时出现意外行为。
    etcdOptions := *commandOptions.Etcd
    etcdOptions.StorageConfig.Paging = utilfeature.DefaultFeatureGate.Enabled(features.APIListChunking)
    // 这是真正的可解码级别。
    etcdOptions.StorageConfig.Codec = apiextensionsapiserver.Codecs.LegacyCodec(v1beta1.SchemeGroupVersion, v1.SchemeGroupVersion)
    // 对于存储，优先选择更紧凑的序列化（v1beta1），直到 https://issue.k8s.io/82292 对那些v1序列化太大但v1beta1序列化可以存储的对象进行解决
    etcdOptions.StorageConfig.EncodeVersioner = runtime.NewMultiGroupVersioner(v1beta1.SchemeGroupVersion, schema.GroupKind{Group: v1beta1.GroupName})
    etcdOptions.SkipHealthEndpoints = true // 避免重复连接健康检查
    if err := etcdOptions.ApplyTo(&genericConfig); err != nil {
        return nil, err
    }

    // 使用apiextensions的默认值和注册表覆盖MergedResourceConfig
    if err := commandOptions.APIEnablement.ApplyTo(
        &genericConfig,
        apiextensionsapiserver.DefaultAPIResourceConfigSource(),
        apiextensionsapiserver.Scheme); err != nil {
        return nil, err
    }
    crdRESTOptionsGetter, err := apiextensionsoptions.NewCRDRESTOptionsGetter(etcdOptions)
    if err != nil {
        return nil, err
    }
    apiextensionsConfig := &apiextensionsapiserver.Config{
        GenericConfig: &genericapiserver.RecommendedConfig{
            Config:                genericConfig,
            SharedInformerFactory: externalInformers,
        },
        ExtraConfig: apiextensionsapiserver.ExtraConfig{
            CRDRESTOptionsGetter: crdRESTOptionsGetter,
            MasterCount:          masterCount,
            AuthResolverWrapper:  authResolverWrapper,
            ServiceResolver:      serviceResolver,
        },
    }

   // 需要清除poststarthooks，以免将它们多次添加到所有服务器（这会导致失败）
    apiextensionsConfig.GenericConfig.PostStartHooks = map[string]genericapiserver.PostStartHookConfigEntry{}

    return apiextensionsConfig, nil
}
```

```go
type Config struct {
    GenericConfig *genericapiserver.RecommendedConfig // 通用配置
    ExtraConfig ExtraConfig // 额外配置
}

type RecommendedConfig struct {
	Config
    // SharedInformerFactory为Kubernetes资源提供共享的Informers。该值由RecommendedOptions.CoreAPI.ApplyTo在RecommendedOptions.ApplyTo中设置。
    // 默认情况下，它使用in-cluster客户端配置，或者使用kubeconfig命令行标志给定的kubeconfig。
    SharedInformerFactory informers.SharedInformerFactory

    // ClientConfig保存Kubernetes客户端配置。
    // 该值由RecommendedOptions.CoreAPI.ApplyTo在RecommendedOptions.ApplyTo中设置。
    // 默认情况下，使用in-cluster客户端配置。
    ClientConfig *restclient.Config
}
```

#### DefaultAPIResourceConfigSource

```go
func DefaultAPIResourceConfigSource() *serverstorage.ResourceConfig {
ret := serverstorage.NewResourceConfig()
    // 注意：在这里列出的GroupVersions将默认启用。不要在列表中放入alpha版本。
    ret.EnableVersions(
        v1beta1.SchemeGroupVersion,
        v1.SchemeGroupVersion,
    )
}
```

#### NewCRDRESTOptionsGetter

```go
// NewCRDRESTOptionsGetter为CustomResources创建一个RESTOptionsGetter。
// 这在etcd选项的副本上工作，以免改变原始值。
// 我们假设输入的etcd选项已经完成。
// 避免对StorageConfig之外的任何内容进行更改，以免在应用选项时出现意外行为。
func NewCRDRESTOptionsGetter(etcdOptions genericoptions.EtcdOptions) (genericregistry.RESTOptionsGetter, error) {
    etcdOptions.StorageConfig.Codec = unstructured.UnstructuredJSONScheme
    etcdOptions.WatchCacheSizes = nil // 这个控制对于自定义资源没有提供
    etcdOptions.SkipHealthEndpoints = true // 避免重复连接健康检查
	// 创建用于变异etcdOptions的通用apiserver配置
    c := genericapiserver.Config{}
    if err := etcdOptions.ApplyTo(&c); err != nil {
        return nil, err
    }
    restOptionsGetter := c.RESTOptionsGetter
    if restOptionsGetter == nil {
        return nil, fmt.Errorf("server.Config的RESTOptionsGetter不应为nil")
    }
    // 检查确保没有设置其他字段
    c.RESTOptionsGetter = nil
    if !reflect.DeepEqual(c, genericapiserver.Config{}) {
        return nil, fmt.Errorf("server.Config中只应该变异RESTOptionsGetter")
    }
    return restOptionsGetter, nil
}
```

### notfoundhandler.New

```go
// New函数返回一个HTTP处理程序，应在委托链的最后执行。
// 它检查请求是否在服务器安装了所有已知的HTTP路径之前发出。
// 如果是这种情况，它返回503响应；否则返回404。
//
// 注意，我们不希望在readyz路径上添加额外的检查，因为这可能阻止修复损坏的集群。
// 此特定处理程序旨在在路径和处理程序完全初始化之前“保护”到达的请求。
func New(serializer runtime.NegotiatedSerializer, isMuxAndDiscoveryCompleteFn func(ctx context.Context) bool) *Handler {
	return &Handler{serializer: serializer, isMuxAndDiscoveryCompleteFn: isMuxAndDiscoveryCompleteFn}
}

type Handler struct {
    serializer runtime.NegotiatedSerializer
    isMuxAndDiscoveryCompleteFn func(ctx context.Context) bool
}

func (h *Handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !h.isMuxAndDiscoveryCompleteFn(req.Context()) {
		errMsg := "the request has been made before all known HTTP paths have been installed, please try again"
		err := apierrors.NewServiceUnavailable(errMsg)
		if err.ErrStatus.Details == nil {
			err.ErrStatus.Details = &metav1.StatusDetails{}
		}
		err.ErrStatus.Details.RetryAfterSeconds = int32(5)

		gv := schema.GroupVersion{Group: "unknown", Version: "unknown"}
		requestInfo, ok := apirequest.RequestInfoFrom(req.Context())
		if ok {
			gv.Group = requestInfo.APIGroup
			gv.Version = requestInfo.APIVersion
		}
		responsewriters.ErrorNegotiated(err, h.serializer, gv, rw, req)
		return
	}
	http.NotFound(rw, req)
}
```

### createAPIExtensionsServer

```go
func createAPIExtensionsServer(apiextensionsConfig *apiextensionsapiserver.Config, delegateAPIServer genericapiserver.DelegationTarget) (*apiextensionsapiserver.CustomResourceDefinitions, error) {
	return apiextensionsConfig.Complete().New(delegateAPIServer)
}

func (cfg *Config) Complete() CompletedConfig {
    // ... 设置一些 默认config
	return CompletedConfig{&c}
}
```

