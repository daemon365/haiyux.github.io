---
title: "kubelet 代码走读"
subtitle:
date: 2023-06-05T21:05:29+08:00
draft: false
toc: true
categories: [cloud]
tags: [kubernetes]
authors:
    - haiyux
---

## 简介

Kubelet是Kubernetes集群中的一个核心组件，它运行在每个节点上，负责管理和维护该节点上的容器。作为Kubernetes的代理，Kubelet负责与主控平面通信，接收主控平面下发的任务，并确保节点上的容器按照规定的状态和配置运行。

Kubelet的主要职责包括：

1. 容器生命周期管理：Kubelet负责监控节点上的容器，并根据主控平面下发的指令创建、启动、停止和销毁容器。它会通过与容器运行时接口（Container Runtime Interface，CRI）进行通信，与底层容器运行时（如Docker、containerd等）交互来管理容器的生命周期。
2. 资源管理：Kubelet负责监控节点的资源使用情况，包括CPU、内存、磁盘和网络等。它会根据容器的资源需求和节点的可用资源进行调度决策，确保节点资源得到合理利用。
3. 容器健康检查：Kubelet定期检查容器的健康状态，包括容器的运行状态、资源利用情况以及应用程序的自定义健康检查。如果发现容器不健康，Kubelet会通知主控平面，由主控平面采取相应的措施，如重启容器或迁移到其他节点上。
4. 节点状态报告：Kubelet向主控平面定期报告节点的状态信息，包括节点的健康状态、资源使用情况、已运行的容器列表等。这些信息对于集群的监控和管理非常重要。
5. 安全性管理：Kubelet负责确保容器的安全性，包括通过在容器中设置正确的Linux命名空间、安全上下文和访问控制等来隔离容器之间的环境。它还会与主控平面协同工作，确保只有经过授权的镜像和容器被部署和运行。

## main

```go
func main() {
	command := app.NewKubeletCommand()
	code := cli.Run(command)
	os.Exit(code)
}

// NewKubeletCommand函数创建一个具有默认参数的*cobra.Command对象。
func NewKubeletCommand() *cobra.Command {
    // 创建FlagSet对象cleanFlagSet，用于处理kubelet组件的标志。
    cleanFlagSet := pflag.NewFlagSet(componentKubelet, pflag.ContinueOnError)
    cleanFlagSet.SetNormalizeFunc(cliflag.WordSepNormalizeFunc)
	// 创建KubeletFlags对象kubeletFlags，用于存储kubelet的标志。
kubeletFlags := options.NewKubeletFlags()

// 创建KubeletConfiguration对象kubeletConfig，用于存储kubelet的配置信息。
kubeletConfig, err := options.NewKubeletConfiguration()
// 程序员错误
if err != nil {
	// 输出错误日志并退出程序
	klog.ErrorS(err, "Failed to create a new kubelet configuration")
	os.Exit(1)
}

// 创建*cobra.Command对象cmd，用于定义kubelet命令的行为和参数。
cmd := &cobra.Command{
	Use: componentKubelet,
	Long: `The kubelet is the primary "node agent" that runs on each
node. It can register the node with the apiserver using one of: the hostname; a flag to
override the hostname; or specific logic for a cloud provider.

The kubelet works in terms of a PodSpec. A PodSpec is a YAML or JSON object
that describes a pod. The kubelet takes a set of PodSpecs that are provided through
various mechanisms (primarily through the apiserver) and ensures that the containers
described in those PodSpecs are running and healthy. The kubelet doesn't manage
containers which were not created by Kubernetes.

Other than from an PodSpec from the apiserver, there are two ways that a container
manifest can be provided to the Kubelet.

File: Path passed as a flag on the command line. Files under this path will be monitored
periodically for updates. The monitoring period is 20s by default and is configurable
via a flag.

HTTP endpoint: HTTP endpoint passed as a parameter on the command line. This endpoint
is checked every 20 seconds (also configurable with a flag).`,
		DisableFlagParsing: true, // 禁用Cobra的标志解析
        SilenceUsage: true, // 不显示用法帮助信息
        RunE: func(cmd *cobra.Command, args []string) error {
            // 初始标志解析，因为禁用了Cobra的标志解析
            if err := cleanFlagSet.Parse(args); err != nil {
                return fmt.Errorf("failed to parse kubelet flag: %w", err)
            }
    		// 检查命令行中是否有非标志参数
            cmds := cleanFlagSet.Args()
            if len(cmds) > 0 {
                return fmt.Errorf("unknown command %+s", cmds[0])
            }

            // 检查是否有帮助标志
            help, err := cleanFlagSet.GetBool("help")
            if err != nil {
                return errors.New(`"help" flag is non-bool, programmer error, please correct`)
            }
            if help {
                return cmd.Help()
            }

            // 检查是否有版本标志
            verflag.PrintAndExitIfRequested()

            // 根据初始的标志配置设置功能门限
            if err := utilfeature.DefaultMutableFeatureGate.SetFromMap(kubeletConfig.FeatureGates); err != nil {
                return fmt.Errorf("failed to set feature gates from initial flags-based config: %w", err)
            }

            // 验证初始的KubeletFlags
            if err := options.ValidateKubeletFlags(kubeletFlags); err != nil {
                return fmt.Errorf("failed to validate kubelet flags: %w", err)
            }

            // 如果更改了"pod-infra-container-image"标志，则打印警告信息
            if cleanFlagSet.Changed("pod-infra-container-image") {
                klog.InfoS("--pod-infra-container-image will not be pruned by the image garbage collector in kubelet and should also be set in the remote runtime")
            }

            // 加载kubelet配置文件（如果提供了）
            if configFile := kubeletFlags.KubeletConfigFile; len(configFile) > 0 {
                kubeletConfig, err = loadConfigFile(configFile)
                if err != nil {
                    return fmt.Errorf("failed to load kubelet config file, error: %w, path: %s", err, configFile)
                }
                // 必须通过重新解析命令行将新对象中的标志配置提升为优先级。
                // 这是为了保持二进制升级的向后兼容性。
                // 更多细节请参见问题＃56171。
                if err := kubeletConfigFlagPrecedence(kubeletConfig, args); err != nil {
                    return fmt.Errorf("failed to precedence kubeletConfigFlag: %w", err)
                }
                // 根据新配置更新功能门限
                if err := utilfeature.DefaultMutableFeatureGate.SetFromMap(kubeletConfig.FeatureGates); err != nil {
                    return fmt.Errorf("failed to set feature gates from initial flags-based config: %w", err)
                }
            }

            // 配置和标志解析完成，现在可以初始化日志记录。
            logs.InitLogs()
            if err := logsapi.ValidateAndApplyAsField(&kubeletConfig.Logging, utilfeature.DefaultFeatureGate, field.NewPath("logging")); err != nil {
                return fmt.Errorf("initialize logging: %v", err)
            }
            cliflag.PrintFlags(cleanFlagSet)

            // 始终验证本地配置（命令行 + 配置文件）。
            // 这是动态配置的默认“最后已知良好”配置，必须始终保持有效。
            if err := kubeletconfigvalidation.ValidateKubeletConfiguration(kubeletConfig, utilfeature.DefaultFeatureGate); err != nil {
                return fmt.Errorf("failed to validate kubelet configuration, error: %w, path: %s", err, kubeletConfig)
            }

            // 检查kubeletCgroups是否在kubeReservedCgroup之内
            if (kubeletConfig.KubeletCgroups != "" && kubeletConfig.KubeReservedCgroup != "") && (strings.Index(kubeletConfig.KubeletCgroups, kubeletConfig.KubeReservedCgroup) != 0) {
                klog.InfoS("unsupported configuration:KubeletCgroups is not within KubeReservedCgroup")
            }

            // 使用kubeletFlags和kubeletConfig构造KubeletServer对象
            kubeletServer := &options.KubeletServer{
                KubeletFlags:         *kubeletFlags,
                KubeletConfiguration: *kubeletConfig,
            }

            // 使用kubeletServer构造默认的KubeletDeps
            kubeletDeps, err := UnsecuredDependencies(kubeletServer, utilfeature.DefaultFeatureGate)
            if err != nil {
                return fmt.Errorf("failed to construct kubelet dependencies: %w", err)
            }

            // 检查权限
            if err := checkPermissions(); err != nil {
                klog.ErrorS(err, "kubelet running with insufficient permissions")
            }

            // 使kubelet的配置安全以供日志记录
            config := kubeletServer.KubeletConfiguration.DeepCopy()
            for k := range config.StaticPodURLHeader {
                config.StaticPodURLHeader[k] = []string{"<masked>"}
            }
            // 记录kubelet的配置以供检查
            klog.V(5).InfoS("KubeletConfiguration", "configuration", klog.Format(config))

            // 设置信号上下文以进行kubelet关闭
            ctx := genericapiserver.SetupSignalContext()

            utilfeature.DefaultMutableFeatureGate.AddMetrics()
            // 运行kubelet
            return Run(ctx, kubeletServer, kubeletDeps, utilfeature.DefaultFeatureGate)
        },
    }

    // 将cleanFlagSet保持独立，以免Cobra将其与全局标志混淆
    kubeletFlags.AddFlags(cleanFlagSet)
    options.AddKubeletConfigFlags(cleanFlagSet, kubeletConfig)
    options.AddGlobalFlags(cleanFlagSet)
    cleanFlagSet.BoolP("help", "h", false, fmt.Sprintf("help for %s", cmd.Name()))

    // 由于Cobra的默认UsageFunc和HelpFunc会将flagset与全局标志混淆，因此需要以下操作
    const usageFmt = "Usage:\n  %s\n\nFlags:\n%s"
    cmd.SetUsageFunc(func(cmd *cobra.Command) error {
        fmt.Fprintf(cmd.OutOrStderr(), usageFmt, cmd.UseLine(), cleanFlagSet.FlagUsagesWrapped(2))
        return nil
    })
    cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
        fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n"+usageFmt, cmd.Long, cmd.UseLine(), cleanFlagSet.FlagUsagesWrapped(2))
    })

    return cmd
}
```

### KubeletConfiguration

```go
// KubeletConfiguration包含Kubelet的配置信息
type KubeletConfiguration struct {
	metav1.TypeMeta
    // enableServer启用Kubelet的安全服务器。
    // 注意：Kubelet的不安全端口由readOnlyPort选项控制。
    EnableServer bool
    // staticPodPath是包含本地（静态）Pod要运行的目录的路径，或者是单个静态Pod文件的路径。
    StaticPodPath string
    // syncFrequency是同步正在运行的容器和配置之间的最大时间间隔
    SyncFrequency metav1.Duration
    // fileCheckFrequency是检查配置文件是否有新数据的时间间隔
    FileCheckFrequency metav1.Duration
    // httpCheckFrequency是检查http是否有新数据的时间间隔
    HTTPCheckFrequency metav1.Duration
    // staticPodURL是访问要运行的静态Pod的URL
    StaticPodURL string
    // staticPodURLHeader是一个带有访问podURL时使用的HTTP标头的切片映射
    StaticPodURLHeader map[string][]string `datapolicy:"token"`
    // address是Kubelet要提供的IP地址（对于所有接口设置为0.0.0.0）
    Address string
    // port是Kubelet要提供的端口。
    Port int32
    // readOnlyPort是Kubelet用于提供无身份验证/授权的只读端口（设置为0以禁用）
    ReadOnlyPort int32
    // volumePluginDir是用于搜索其他第三方卷插件的目录的完整路径。
    VolumePluginDir string
    // providerID（如果设置）设置外部提供程序（即cloudprovider）用于标识特定节点的唯一ID
    ProviderID string
    // tlsCertFile是包含HTTPS的x509证书的文件。 （CA证书，
    // 如果有的话，在服务器证书之后连接在一起）。如果未提供tlsCertFile和
    // tlsPrivateKeyFile，将为公共地址生成自签名证书
    // 并将其保存到传递给Kubelet的--cert-dir标志的目录中。
    TLSCertFile string
    // tlsPrivateKeyFile是包含与tlsCertFile匹配的x509私钥的文件
    TLSPrivateKeyFile string
    // TLSCipherSuites是服务器允许的密码套件列表。
    // 请注意，TLS 1.3密码套件不可配置。
    // 值来自tls包的常量（https://golang.org/pkg/crypto/tls/#pkg-constants）。
    TLSCipherSuites []string
    // TLSMinVersion是支持的最低TLS版本。
    // 值来自tls包的常量（https://golang.org/pkg/crypto/tls/#pkg-constants）。
    TLSMinVersion string
    // rotateCertificates启用客户端证书轮换。 Kubelet将从certificates.k8s.io API请求一个
    // 新的证书。 这需要一个批准者来批准证书签名请求。
    RotateCertificates bool
    // serverTLSBootstrap启用服务器证书引导。 Kubelet将从
	// serverTLSBootstrap 启用服务器证书引导。Kubelet将从 certificates.k8s.io API 请求证书，而不是自签名的服务证书。这需要一个批准者来批准证书签名请求。RotateKubeletServerCertificate 功能必须被启用。
    ServerTLSBootstrap bool

    // authentication 指定了Kubelet服务器上的请求如何进行身份验证
    Authentication KubeletAuthentication

    // authorization 指定了Kubelet服务器上的请求如何进行授权
    Authorization KubeletAuthorization

    // registryPullQPS 是每秒钟的镜像拉取次数限制。设置为0表示没有限制。
    RegistryPullQPS int32

    // registryBurst 是突发拉取的最大大小，临时允许拉取到此数量，但仍不能超过 registryPullQPS。仅在 registryPullQPS > 0 时使用。
    RegistryBurst int32

    // eventRecordQPS 是每秒钟的事件创建次数限制。如果为0，没有强制限制。
    EventRecordQPS int32

    // eventBurst 是事件创建突发的最大大小，临时允许事件创建到此数量，但仍不能超过 eventRecordQPS。仅在 eventRecordQPS > 0 时使用。
    EventBurst int32

    // enableDebuggingHandlers 启用服务器端点，用于日志收集和本地运行容器和命令。
    EnableDebuggingHandlers bool

    // enableContentionProfiling 如果 enableDebuggingHandlers 为 true，则启用阻塞分析。
    EnableContentionProfiling bool

    // healthzPort 是本地主机 healthz 端点的端口（设置为0表示禁用）
    HealthzPort int32

    // healthzBindAddress 是 healthz 服务器要侦听的 IP 地址
    HealthzBindAddress string

    // oomScoreAdj 是 kubelet 进程的 oom-score-adj 值。值必须在 [-1000, 1000] 范围内。
    OOMScoreAdj int32

    // clusterDomain 是此集群的 DNS 域。如果设置，Kubelet 将配置所有容器以在主机的搜索域之外搜索此域。
    ClusterDomain string

    // clusterDNS 是群集 DNS 服务器的 IP 地址列表。如果设置，Kubelet 将配置所有容器使用该地址进行 DNS 解析，而不是主机的 DNS 服务器。
    ClusterDNS []string

    // streamingConnectionIdleTimeout 是流式连接在自动关闭之前可以空闲的最长时间。
    StreamingConnectionIdleTimeout metav1.Duration

    // nodeStatusUpdateFrequency 是 Kubelet 计算节点状态的频率。如果未启用节点租约功能，它还是 Kubelet 将节点状态发布到主节点的频率。在这种情况下，更改此常量时要小心，它必须与 nodecontroller 中的 nodeMonitorGracePeriod 配合使用。
    NodeStatusUpdateFrequency metav1.Duration

    // nodeStatusReportFrequency 是 kubelet 在节点状态未发生变化时向主节点发送节点状态的频率。如果检测到任何变化，kubelet 将忽略此频率并立即发送节点状态。仅在启用节点租约功能时使用。
    NodeStatusReportFrequency metav1.Duration
    // nodeLeaseDurationSeconds 是 Kubelet 将设置在其相应租约上的持续时间。
    NodeLeaseDurationSeconds int32
    // imageMinimumGCAge 是未使用的镜像在进行垃圾回收之前的最小年龄。
    ImageMinimumGCAge metav1.Duration
    // imageGCHighThresholdPercent 是磁盘使用率超过此阈值时始终运行镜像垃圾回收的百分比。百分比是根据此字段的值计算的，范围为 0-100。
    ImageGCHighThresholdPercent int32
    // imageGCLowThresholdPercent 是磁盘使用率低于此阈值时不运行镜像垃圾回收的百分比。最低磁盘使用率以进行垃圾回收。百分比是根据此字段的值计算的，范围为 0-100。
    ImageGCLowThresholdPercent int32
    // 每隔多长时间计算并缓存所有 pod 的卷磁盘使用情况。
    VolumeStatsAggPeriod metav1.Duration
    // KubeletCgroups 是用于隔离 kubelet 的 cgroups 的绝对名称。
    KubeletCgroups string
    // SystemCgroups 是放置所有非内核进程（尚未在容器中的所有进程）的 cgroups 的绝对名称。如果为空，则表示没有容器。回滚标志需要重新启动。
    SystemCgroups string
    // CgroupRoot 是用于 pod 的根 cgroup。如果启用了 CgroupsPerQOS，则这是 QoS cgroup 层次结构的根。
    CgroupRoot string
    // 启用基于 QoS 的 Cgroup 层次结构：用于 QoS 类别的顶级 cgroups，所有 Burstable 和 BestEffort pod 都在其特定的顶级 QoS cgroup 下启动。
    CgroupsPerQOS bool
    // kubelet 在主机上操作 cgroups 的驱动程序（cgroupfs 或 systemd）。
    CgroupDriver string
    // CPUManagerPolicy 是要使用的策略的名称。需要启用 CPUManager 功能门。
    CPUManagerPolicy string
    // CPUManagerPolicyOptions 是一个键值对集合，允许设置额外的选项来微调 CPU 管理器策略的行为。需要同时启用 "CPUManager" 和 "CPUManagerPolicyOptions" 功能门。
    CPUManagerPolicyOptions map[string]string
    // CPUManagerReconcilePeriod 是 CPU 管理器调谐的周期。需要启用 CPUManager 功能门。
    CPUManagerReconcilePeriod metav1.Duration
    // MemoryManagerPolicy 是要使用的策略的名称。需要启用 MemoryManager 功能门。
    MemoryManagerPolicy string
    // TopologyManagerPolicy 是要使用的策略的.
	// TopologyManagerPolicy 是要使用的策略的名称。
    TopologyManagerPolicy string

    // TopologyManagerScope 表示拓扑提示生成的范围，拓扑管理器请求和提示提供程序生成。
    // 默认值："container"
    // +optional
    TopologyManagerScope string

    // TopologyManagerPolicyOptions 是一组 key=value 键值对，允许设置额外的选项来微调拓扑管理器策略的行为。
    // 需要同时启用 "TopologyManager" 和 "TopologyManagerPolicyOptions" 功能门。
    TopologyManagerPolicyOptions map[string]string

    // QOSReserved 是 QoS 资源预留百分比的映射（目前仅限内存）。
    // 需要启用 QOSReserved 功能门。
    QOSReserved map[string]string

    // runtimeRequestTimeout 是除了长时间运行请求（如拉取、日志、执行和附加）之外所有运行时请求的超时时间。
    RuntimeRequestTimeout metav1.Duration

    // hairpinMode 指定 Kubelet 如何配置容器网桥以处理 hairpin 数据包。
    // 设置此标志允许 Service 中的端点在尝试访问自己的 Service 时进行负载均衡返回到自己。
    // 可选值："promiscuous-bridge"：使容器网桥处于混杂模式。
    // "hairpin-veth"：在容器 veth 接口上设置 hairpin 标志。
    // "none"：什么都不做。
    // 通常，必须设置 --hairpin-mode=hairpin-veth 才能实现 hairpin NAT，因为 promiscuous-bridge 假定存在名为 cbr0 的容器网桥。
    HairpinMode string

    // MaxPods 是此 Kubelet 可以运行的 Pod 数量。
    MaxPods int32

    // PodCIDR 是用于 Pod IP 地址的 CIDR，仅在独立模式下使用。
    // 在集群模式下，此值从主节点获取。
    PodCIDR string

    // PodPidsLimit 是每个 Pod 的最大进程数。如果为 -1，则 Kubelet 默认为节点可分配的 PID 容量。
    PodPidsLimit int64

    // ResolverConfig 是用作容器 DNS 解析配置基础的解析器配置文件。
    ResolverConfig string

    // RunOnce 导致 Kubelet 仅检查 API 服务器一次以获取 Pod，
    // 在静态 Pod 文件指定的 Pod 之外运行这些 Pod，并退出。
    RunOnce bool

    // cpuCFSQuota 启用对指定 CPU 限制的容器启用 CPU CFS 配额强制。
    CPUCFSQuota bool

    // CPUCFSQuotaPeriod 设置 CPU CFS 配额周期值，即 cpu.cfs_period_us，默认为 100ms。
    CPUCFSQuotaPeriod metav1.Duration

    // MaxOpenFiles 是 Kubelet 进程可以打开的文件数量。
    MaxOpenFiles int64

    // nodeStatusMaxImages 限制在 Node.Status.Images 中报告的映像数量。
    NodeStatusMaxImages int32

    // contentType 是发送到 API 服务器的请求的内容类型。
    ContentType string

    // KubeAPIQPS 是与 Kubernetes API 服务器通信时使用的 QPS。
    KubeAPIQPS int32

    // KubeAPIBurst 是与 Kubernetes API 服务器通信时允许的突发大小。
    KubeAPIBurst int32

    // serializeImagePulls 在启用时，告诉 Kubelet 一次拉取一个镜像。
    SerializeImagePulls bool

    // MaxParallelImagePulls 设置并行进行的最大镜像拉取数。
    MaxParallelImagePulls *int32

    // EvictionHard 是一个信号名称到数量的映射，定义硬驱逐阈值。
    // 例如：{"memory.available": "300Mi"}。
    // 一些默认信号仅适用于 Linux：nodefs.inodesFree。
    EvictionHard map[string]string

    // EvictionSoft 是一个信号名称到数量的映射，定义软驱逐阈值。
    // 例如：{"memory.available": "300Mi"}。
    EvictionSoft map[string]string

    // EvictionSoftGracePeriod 是一个信号名称到数量的映射，定义每个软驱逐信号的宽限期。
    // 例如：{"memory.available": "30s"}。
    EvictionSoftGracePeriod map[string]string

    // EvictionPressureTransitionPeriod 是在转换出驱逐压力条件之前 Kubelet 必须等待的持续时间。
    EvictionPressureTransitionPeriod metav1.Duration

    // EvictionMaxPodGracePeriod 是在满足软驱逐阈值时终止 Pod 的最大容忍期（以秒为单位）。
    EvictionMaxPodGracePeriod int32

    // EvictionMinimumReclaim 是一个信号名称到数量的映射，定义在资源压力下进行 Pod 驱逐时 Kubelet 将回收的最小数量。
    // 例如：{"imagefs.available": "2Gi"}。
    EvictionMinimumReclaim map[string]string

    // PodsPerCore 是每个核心的最大 Pod 数量。不能超过 MaxPods。
    // 如果为 0，则忽略此字段。
    PodsPerCore int32

    // enableControllerAttachDetach 启用 Attach/Detach 控制器以管理安排给该节点的卷的附加/分离，并禁用 Kubelet 执行任何附加/分离操作。
    EnableControllerAttachDetach bool

    // protectKernelDefaults 如果为 true，则使 Kubelet 在内核标志不符合预期时报错。否则，Kubelet 将尝试修改内核标志以与其预期相匹配。
    ProtectKernelDefaults bool

    // 如果为 true，则 Kubelet 确保主机上存在一组 iptables 规则。
    // 这些规则将作为各个组件的实用程序，如 kube-proxy，而创建。
    // 这些规则将根据 IPTablesMasqueradeBit 和 IPTablesDropBit 创建。
    MakeIPTablesUtilChains bool

    // IPTablesMasqueradeBit 是 iptables fwmark 空间中用于标记 SNAT 的位。
    // 值必须在范围 [0, 31] 内。必须与其他标记位不同。
    // 警告：请与 kube-proxy 中的相应参数的值匹配。
    // TODO：清理 kube-proxy 中的 IPTablesMasqueradeBit
    IPTablesMasqueradeBit int32

    // iptablesDropBit 是 iptables fwmark 空间中用于标记丢弃数据包的位。
    // 值必须在范围 [0, 31] 内。必须与其他标记位不同。
    IPTablesDropBit int32

    // featureGates 是一个功能名称到布尔值的映射，用于启用或禁用 alpha/experimental 功能。
    // 此字段逐个修改从 "k8s.io/kubernetes/pkg/features/kube_features.go" 中内置的默认值。
    FeatureGates map[string]bool

    // 告诉 Kubelet 如果节点上启用了交换空间，则无法启动。
    FailSwapOn bool

    // memorySwap 配置可供容器工作负载使用的交换空间内存。
    // +featureGate=NodeSwap
    // +optional
    MemorySwap MemorySwapConfiguration

    // quantity 定义容器日志文件在进行轮换之前的最大大小。例如："5Mi" 或 "256Ki"。
    ContainerLogMaxSize string

    // 可以存在于容器的最大容器日志文件数。
    ContainerLogMaxFiles int32

    // ConfigMapAndSecretChangeDetectionStrategy 是 config map 和 secret 管理器运行的模式。
    ConfigMapAndSecretChangeDetectionStrategy ResourceChangeDetectionStrategy

    // 一个以逗号分隔的不安全 sysctl 或 sysctl 模式（以 * 结尾）的白名单。
    // 不安全的 sysctl 组包括 kernel.shm*、kernel.msg*、kernel.sem、fs.mqueue.* 和 net.*。
    // 这些 sysctl 在命名空间中，但默认情况下不允许使用。
    // 例如："kernel.msg*,net.ipv4.route.min_pmtu"
    // +optional
    AllowedUnsafeSysctls []string

    // 如果启用，Kubelet 将与内核 memcg 通知集成，以确定是否跨越内存驱逐阈值，而不是轮询。
    KernelMemcgNotification bool
    /* 以下字段用于节点可分配资源 */

	// 一组以ResourceName=ResourceQuantity（例如cpu=200m，memory=150G，ephemeral-storage=1G，pid=100）对描述的资源
    // 用于保留给非 Kubernetes 组件的资源
    // 目前仅支持cpu、memory和本地临时存储（用于根文件系统）
    // 有关更多详细信息，请参阅 http://kubernetes.io/docs/user-guide/compute-resources
	SystemReserved map[string]string
	// 一组以ResourceName=ResourceQuantity（例如cpu=200m，memory=150G，ephemeral-storage=1G，pid=100）对描述的资源
    // 用于保留给 Kubernetes 系统组件的资源
    // 目前仅支持cpu、memory和本地临时存储（用于根文件系统）
    // 有关更多详细信息，请参阅 http://kubernetes.io/docs/user-guide/compute-resources
	KubeReserved map[string]string
	// 此标志用于帮助 kubelet 标识用于强制执行“SystemReserved”计算资源预留的操作系统系统守护程序的顶级cgroup的绝对名称
	// 有关详细信息，请参阅 [Node Allocatable](https://kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/#node-allocatable) 文档
	SystemReservedCgroup string
	// 此标志用于帮助 kubelet 标识用于强制执行“KubeReserved”计算资源预留的 Kubernetes 节点系统守护程序的顶级cgroup的绝对名称
	// 有关详细信息，请参阅 [Node Allocatable](https://kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/#node-allocatable) 文档
	KubeReservedCgroup string
	// 此标志指定 Kubelet 需要执行的各种节点可分配强制性规定
    // 此标志接受一个选项列表。可接受的选项有 `pods`、`system-reserved` 和 `kube-reserved`
    // 有关详细信息，请参阅 [Node Allocatable](https://kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/#node-allocatable) 文档
	EnforceNodeAllocatable []string
	// 此选项指定为主机级别系统线程和与 Kubernetes 相关的线程保留的 CPU 列表
    // 它提供了一个“静态”CPU列表，而不是由 system-reserved 和 kube-reserved 提供的“动态”列表
    // 此选项将覆盖由 system-reserved 和 kube-reserved 提供的 CPU
	ReservedSystemCPUs string
	// 要显示隐藏指标的先前版本
    // 只有先前的次要版本有意义，其他值将不被允许
    // 格式为<major>.<minor>，例如：'1.16'
    // 这种格式的目的是确保您有机会注意到下一个发布是否隐藏了其他指标，
    // 而不是在之后的发布中永久删除它们时感到惊讶
	ShowHiddenMetricsForVersion string
	// Logging 指定日志选项
	// 有关详细信息，请参阅 [Logs Options](https://github.com/kubernetes/component-base/blob/master/logs/options.go) 文档
	Logging logsapi.LoggingConfiguration
	// EnableSystemLogHandler：启用/logs处理程序。
    EnableSystemLogHandler bool

    // EnableSystemLogQuery：在/logs端点上启用节点日志查询功能。
    // 需要同时启用EnableSystemLogHandler才能正常工作。
    // +featureGate=NodeLogQuery
    // +optional
    EnableSystemLogQuery bool

    // ShutdownGracePeriod：指定节点在关机期间应延迟关机和容器终止的总持续时间。
    // 默认为0秒。
    // +featureGate=GracefulNodeShutdown
    // +optional
    ShutdownGracePeriod metav1.Duration

    // ShutdownGracePeriodCriticalPods：指定在关机期间终止关键Pod的持续时间。此时间应小于ShutdownGracePeriod。
    // 默认为0秒。
    // 例如，如果ShutdownGracePeriod=30s，ShutdownGracePeriodCriticalPods=10s，在节点关机期间，前20秒将用于优雅终止普通Pod，最后的10秒将用于终止关键Pod。
    // +featureGate=GracefulNodeShutdown
    // +optional
    ShutdownGracePeriodCriticalPods metav1.Duration

    // ShutdownGracePeriodByPodPriority：根据关联的优先级类值指定Pod的关机宽限期。
    // 当收到关机请求时，Kubelet将根据Pod的优先级启动关机，等待所有Pod退出，并具有依赖于Pod优先级的优雅终止时间间隔。
    // 数组中的每个条目表示具有在节点关闭时位于该值范围及下一个更高条目之间的优先级类值的Pod的优雅关机时间。
    ShutdownGracePeriodByPodPriority []ShutdownGracePeriodByPodPriority

    // ReservedMemory：指定NUMA节点的内存预留的逗号分隔列表。
    // 此参数仅在内存管理器功能上下文中有意义。内存管理器不会为容器工作负载分配保留的内存。
    // 例如，如果您有一个具有10Gi内存的NUMA0节点，并且指定了ReservedMemory以在NUMA0上预留1Gi内存，
    // 则内存管理器将假定可供分配的内存只有9Gi。
    // 您可以指定不同数量的NUMA节点和内存类型。
    // 您可以完全省略此参数，但是您应该知道所有NUMA节点的保留内存量应等于节点可分配特性。
    // 如果至少有一个节点可分配参数具有非零值，则需要指定至少一个NUMA节点。
    // 同时，请避免指定：
    // 1. 重复项，即相同的NUMA节点和内存类型，但具有不同的值。
    // 2. 任何内存类型的零限制。
    // 3. 不存在于机器下的NUMA节点ID。
    // 4. 内存类型（除内存和hugepages-<size>外）。
    ReservedMemory []MemoryReservation

    // EnableProfilingHandler：启用/debug/pprof处理程序。
    EnableProfilingHandler bool

    // EnableDebugFlagsHandler：启用/debug/flags/v处理程序。
    EnableDebugFlagsHandler bool

    // SeccompDefault：启用将RuntimeDefault用作所有工作负载的默认Seccomp配置文件。
    SeccompDefault bool

    // MemoryThrottlingFactor：在设置cgroupv2 memory.high值以执行MemoryQoS时，将内存限制或节点可分配内存乘以的因子。
    // 减小此因子将为容器cgroup设置较低的高限制，并施加更大的回收压力；
    // 增大此因子将施加较少的回收压力。
    // 有关更多详细信息，请参阅https://kep.k8s.io/2570。
    // 默认值为0.9。
    // +featureGate=MemoryQoS
    // +optional
    MemoryThrottlingFactor *float64

    // RegisterWithTaints：在kubelet注册时向节点对象添加的污点数组。
    // 仅当RegisterNode为true并且在节点的初始注册时生效。
    // +optional
    RegisterWithTaints []v1.Taint

    // RegisterNode：启用与apiserver的自动注册。
    // +optional
    RegisterNode bool

    // Tracing：指定OpenTelemetry跟踪客户端的版本化配置。
    // 有关更多详细信息，请参阅https://kep.k8s.io/2832。
    // +featureGate=KubeletTracing
    // +optional
    Tracing *tracingapi.TracingConfiguration

    // LocalStorageCapacityIsolation：启用本地临时存储隔离功能。默认设置为true。
    // 此功能允许用户为容器的临时存储设置请求/限制，并以类似于CPU和内存的方式进行管理。
    // 它还允许设置emptyDir卷的sizeLimit，如果卷的磁盘使用超过限制，则会触发Pod驱逐。
    // 此功能依赖于检测正确的根文件系统磁盘使用情况的能力。
    // 对于某些系统（例如kind rootless），如果无法支持此功能，则应禁用LocalStorageCapacityIsolation。
    // 一旦禁用，用户不应设置容器的临时存储的请求/限制，或者emptyDir的sizeLimit。
    // +optional
    LocalStorageCapacityIsolation bool

    // ContainerRuntimeEndpoint：容器运行时的端点。
    // 在Linux上支持Unix域套接字，而在Windows上支持npipes和tcp端点。
    // 例如：'unix:///path/to/runtime.sock'，'npipe:////./pipe/runtime'。
    ContainerRuntimeEndpoint string

    // ImageServiceEndpoint：容器镜像服务的端点。
    // 如果未指定，默认值为ContainerRuntimeEndpoint。
    // +optional
    ImageServiceEndpoint string
}
```

#### NewKubeletConfiguration

```go
// NewKubeletConfiguration will create a new KubeletConfiguration with default values
// 创建一个具有默认值的新KubeletConfiguration
func NewKubeletConfiguration() (*kubeletconfig.KubeletConfiguration, error) {
	// 创建一个新的Scheme和Codec
	scheme, _, err := kubeletscheme.NewSchemeAndCodecs()
	if err != nil {
		return nil, err
	}

	// 创建一个v1beta1版本的KubeletConfiguration对象
	versioned := &v1beta1.KubeletConfiguration{}
	// 为versioned对象设置默认值
	scheme.Default(versioned)

	// 创建一个KubeletConfiguration对象
	config := &kubeletconfig.KubeletConfiguration{}
	// 将versioned对象转换为config对象
	if err := scheme.Convert(versioned, config, nil); err != nil {
		return nil, err
	}

	// 应用遗留的默认值到KubeletConfiguration
	applyLegacyDefaults(config)

	// 返回config对象和nil作为错误值
	return config, nil
}
```

##### applyLegacyDefaults

```go
// applyLegacyDefaults将遗留的默认值应用到KubeletConfiguration中，以保留命令行API。
// 这用于在第一轮标志解析之前构造基线默认的KubeletConfiguration。
func applyLegacyDefaults(kc *kubeletconfig.KubeletConfiguration) {
	// 设置 --anonymous-auth 标志为true
	kc.Authentication.Anonymous.Enabled = true
	// 设置 --authentication-token-webhook 标志为false
	kc.Authentication.Webhook.Enabled = false
	// 设置 --authorization-mode 标志为kubeletconfig.KubeletAuthorizationModeAlwaysAllow
	kc.Authorization.Mode = kubeletconfig.KubeletAuthorizationModeAlwaysAllow
	// 设置 --read-only-port 标志为ports.KubeletReadOnlyPort
	kc.ReadOnlyPort = ports.KubeletReadOnlyPort
}
```

##### Scheme

```go
// Scheme定义了序列化和反序列化API对象的方法，用于将组、版本和类型信息与Go schemas之间进行转换，
// 以及不同版本的Go schemas之间的映射。Scheme是版本化API和版本化配置的基础。
//
// 在Scheme中，Type是特定的Go结构体，Version是表示该Type的特定时间点的标识符（通常是向后兼容的），
// Kind是该Type在Version中的唯一名称，Group标识一组随时间演变的Versions、Kinds和Types。
// Unversioned Type是尚未正式绑定到类型的Type，并承诺向后兼容（实际上是Type的“v1”，不希望在将来发生变化）。
//
// Scheme在运行时不会发生变化，并且只有在注册完成后才能线程安全。
type Scheme struct {
	// gvkToType允许根据给定的version和name找到对象的go类型。
	gvkToType map[schema.GroupVersionKind]reflect.Type

	// typeToGVK允许找到给定go对象的元数据。
	// 我们索引的reflect.Type *不*应该是指针。
	typeToGVK map[reflect.Type][]schema.GroupVersionKind

	// unversionedTypes在ConvertToVersion中无需进行转换即可进行转换。
	unversionedTypes map[reflect.Type]schema.GroupVersionKind

	// unversionedKinds是在任何组或版本上下文中创建的Kinds的名称集。
	// TODO: 解决unversioned types的状态。
	unversionedKinds map[string]reflect.Type

	// Map from version and resource to the corresponding func to convert
	// resource field labels in that version to internal version.
	fieldLabelConversionFuncs map[schema.GroupVersionKind]FieldLabelConversionFunc

	// defaulterFuncs是一个map，用于提供默认值的函数，该函数将被调用以提供默认值。
	// 提供的对象必须是指针。
	defaulterFuncs map[reflect.Type]func(interface{})

	// converter存储所有注册的转换函数。它还具有默认的转换行为。
	converter *conversion.Converter

	// versionPriority是一个map，将组映射为按优先级排序的版本列表，指示这些版本的默认优先级，
	// 这些版本在scheme中注册时的顺序
	versionPriority map[string][]string

	// observedVersions跟踪我们在类型注册过程中看到的版本的顺序
	observedVersions []schema.GroupVersion

	// schemeName是该scheme的名称。如果不指定名称，则将使用NewScheme调用者的堆栈。
	// 这对于错误报告非常有用，以指示scheme的起源。
	schemeName string
}

// NewSchemeAndCodecs是一个实用函数，返回一个理解kubeletconfig API组中类型的Scheme和CodecFactory。
// 通过传递mutators来调整CodecFactory的行为，例如启用严格解码。
func NewSchemeAndCodecs(mutators ...serializer.CodecFactoryOptionsMutator) (*runtime.Scheme, *serializer.CodecFactory, error) {
	// 创建一个新的Scheme
	scheme := runtime.NewScheme()

	// 将kubeletconfig类型添加到Scheme中
	if err := kubeletconfig.AddToScheme(scheme); err != nil {
		return nil, nil, err
	}

	// 将kubeletconfigv1beta1类型添加到Scheme中
	if err := kubeletconfigv1beta1.AddToScheme(scheme); err != nil {
		return nil, nil, err
	}

	// 将kubeletconfigv1类型添加到Scheme中
	if err := kubeletconfigv1.AddToScheme(scheme); err != nil {
		return nil, nil, err
	}

	// 创建一个CodecFactory，使用Scheme和mutators作为参数
	codecs := serializer.NewCodecFactory(scheme, mutators...)

	// 返回Scheme、CodecFactory和nil作为错误值
	return scheme, &codecs, nil
}
```

### Dependencies

```go
// UnsecuredDependencies返回一个适用于运行的Dependencies，如果服务器设置无效则返回错误。
// 它不会启动任何后台进程，也不包括身份验证/授权。
func UnsecuredDependencies(s *options.KubeletServer, featureGate featuregate.FeatureGate) (*kubelet.Dependencies, error) {
	// 初始化TLS选项
	tlsOptions, err := InitializeTLS(&s.KubeletFlags, &s.KubeletConfiguration)
	if err != nil {
		return nil, err
	}

	mounter := mount.New(s.ExperimentalMounterPath)
	subpather := subpath.New(mounter)
	hu := hostutil.NewHostUtil()
	var pluginRunner = exec.New()

	plugins, err := ProbeVolumePlugins(featureGate)
	if err != nil {
		return nil, err
	}
	tp := oteltrace.NewNoopTracerProvider()
	if utilfeature.DefaultFeatureGate.Enabled(features.KubeletTracing) {
		tp, err = newTracerProvider(s)
		if err != nil {
			return nil, err
		}
	}

	// 返回Dependencies结构的指针，其中包含各种依赖项对象
	return &kubelet.Dependencies{
		Auth:                nil, // 默认情况下不强制执行身份验证
		CAdvisorInterface:   nil, // cadvisor.New启动后台进程（bg http.ListenAndServe和一些bg清理器），这里没有设置
		Cloud:               nil, // 云提供商可能启动后台进程
		ContainerManager:    nil,
		KubeClient:          nil,
		HeartbeatClient:     nil,
		EventClient:         nil,
		TracerProvider:      tp,
		HostUtil:            hu,
		Mounter:             mounter,
		Subpather:           subpather,
		OOMAdjuster:         oom.NewOOMAdjuster(),
		OSInterface:         kubecontainer.RealOS{},
		VolumePlugins:       plugins,
		DynamicPluginProber: GetDynamicPluginProber(s.VolumePluginDir, pluginRunner),
		TLSOptions:          tlsOptions}, nil
}

// Dependencies是我们可能考虑为“注入依赖项”的容器，其中包含了运行Kubelet所必需的在运行时构建的对象。
// 这是一个临时解决方案，用于在我们找出更全面的Kubelet依赖注入机制之前，对这些对象进行分组。
type Dependencies struct {
	Options []Option

	// 注入的依赖项
	Auth                     server.AuthInterface
	CAdvisorInterface        cadvisor.Interface
	Cloud                    cloudprovider.Interface
	ContainerManager         cm.ContainerManager
	EventClient              v1core.EventsGetter
	HeartbeatClient          clientset.Interface
	OnHeartbeatFailure       func()
	KubeClient               clientset.Interface
	Mounter                  mount.Interface
	HostUtil                 hostutil.HostUtils
	OOMAdjuster              *oom.OOMAdjuster
	OSInterface              kubecontainer.OSInterface
	PodConfig                *config.PodConfig
	ProbeManager             prober.Manager
	Recorder                 record.EventRecorder
	Subpather                subpath.Interface
	TracerProvider           trace.TracerProvider
	VolumePlugins            []volume.VolumePlugin
	DynamicPluginProber      volume.DynamicPluginProber
	TLSOptions               *server.TLSOptions
	RemoteRuntimeService     internalapi.RuntimeService
	RemoteImageService       internalapi.ImageManagerService
	PodStartupLatencyTracker util.PodStartupLatencyTracker
	// 在cadvisor.UsingLegacyCadvisorStats被弃用后移除。
	useLegacyCadvisorStats bool
}
```

### Run

```go
// Run函数运行指定的KubeletServer和给定的Dependencies。该函数不应该退出。
// kubeDeps参数可以为nil-如果是nil，则从KubeletServer的设置中进行初始化。
// 否则，假定调用方已经设置了Dependencies对象，不会生成默认的Dependencies对象。
func Run(ctx context.Context, s *options.KubeletServer, kubeDeps *kubelet.Dependencies, featureGate featuregate.FeatureGate) error {
    // 为了帮助调试，立即记录版本信息
    klog.InfoS("Kubelet版本", "kubeletVersion", version.Get())
    // 记录Golang的设置信息
    klog.InfoS("Golang settings", "GOGC", os.Getenv("GOGC"), "GOMAXPROCS", os.Getenv("GOMAXPROCS"), "GOTRACEBACK", os.Getenv("GOTRACEBACK"))

    // 如果初始化操作系统相关设置失败，则返回错误
    if err := initForOS(s.KubeletFlags.WindowsService, s.KubeletFlags.WindowsPriorityClass); err != nil {
        return fmt.Errorf("failed OS init: %w", err)
    }

    // 运行Kubelet
    if err := run(ctx, s, kubeDeps, featureGate); err != nil {
        return fmt.Errorf("failed to run Kubelet: %w", err)
    }

    return nil
}
```

#### run

```go
func run(ctx context.Context, s *options.KubeletServer, kubeDeps *kubelet.Dependencies, featureGate featuregate.FeatureGate) (err error) {
    // 根据初始的 KubeletServer 设置全局的功能门控
    err = utilfeature.DefaultMutableFeatureGate.SetFromMap(s.KubeletConfiguration.FeatureGates)
    if err != nil {
    	return err
    }
    // 验证初始的 KubeletServer（因为这个验证依赖于功能门控的设置，所以我们首先设置功能门控）
    if err := options.ValidateKubeletServer(s); err != nil {
        return err
    }

    // 如果启用了 MemoryQoS 且 cgroups v1 模式下，发出警告
    if utilfeature.DefaultFeatureGate.Enabled(features.MemoryQoS) &&
        !isCgroup2UnifiedMode() {
        klog.InfoS("Warning: MemoryQoS feature only works with cgroups v2 on Linux, but enabled with cgroups v1")
    }

    // 如果要求在文件锁争用时退出但未指定锁文件路径，返回错误
    if s.ExitOnLockContention && s.LockFilePath == "" {
        return errors.New("cannot exit on lock file contention: no lock file specified")
    }

    done := make(chan struct{})
    // 如果指定了锁文件路径，获取锁文件
    if s.LockFilePath != "" {
        klog.InfoS("Acquiring file lock", "path", s.LockFilePath)
        if err := flock.Acquire(s.LockFilePath); err != nil {
            return fmt.Errorf("unable to acquire file lock on %q: %w", s.LockFilePath, err)
        }
        // 如果要求在锁文件争用时退出，监视锁文件内容的变化
        if s.ExitOnLockContention {
            klog.InfoS("Watching for inotify events", "path", s.LockFilePath)
            if err := watchForLockfileContention(s.LockFilePath, done); err != nil {
                return err
            }
        }
    }

    // 使用初始的 Kubelet 配置在 /configz 端点注册当前配置
    err = initConfigz(&s.KubeletConfiguration)
    if err != nil {
        klog.ErrorS(err, "Failed to register kubelet configuration with configz")
    }

    // 如果设置了 ShowHiddenMetricsForVersion，显示隐藏指标
    if len(s.ShowHiddenMetricsForVersion) > 0 {
        metrics.SetShowHidden()
    }

    // 准备获取客户端等操作之前，检测是否处于独立模式
    standaloneMode := true
    if len(s.KubeConfig) > 0 {
        standaloneMode = false
    }

    // 如果未提供 kubeDeps，则构建 UnsecuredDependencies
    if kubeDeps == nil {
        kubeDeps, err = UnsecuredDependencies(s, featureGate)
        if err != nil {
            return err
        }
    }

    // 如果 kubeDeps 中的 Cloud 为 nil，则根据 CloudProvider 初始化 cloud
    if kubeDeps.Cloud == nil {
        // 如果kubeDeps.Cloud为nil，则执行以下代码块
        if !cloudprovider.IsExternal(s.CloudProvider) {
            // 如果s.CloudProvider不是外部提供商，则执行以下代码块
            cloudprovider.DeprecationWarningForProvider(s.CloudProvider)
            // 发出有关提供程序过时的警告
            cloud, err := cloudprovider.InitCloudProvider(s.CloudProvider, s.CloudConfigFile)
            // 初始化云提供程序
            if err != nil {
                return err
            }
            if cloud != nil {
                // 如果云提供程序不为nil，则记录成功初始化云提供程序的信息
                klog.V(2).InfoS("Successfully initialized cloud provider", "cloudProvider", s.CloudProvider, "cloudConfigFile", s.CloudConfigFile)
            }
            kubeDeps.Cloud = cloud
        }
    }

    hostName, err := nodeutil.GetHostname(s.HostnameOverride)
    // 获取主机名
    if err != nil {
        return err
    }
    nodeName, err := getNodeName(kubeDeps.Cloud, hostName)
    // 根据云提供程序和主机名获取节点名
    if err != nil {
        return err
    }

    // 如果在独立模式下，将所有客户端设置为nil
    switch {
    case standaloneMode:
        kubeDeps.KubeClient = nil
        kubeDeps.EventClient = nil
        kubeDeps.HeartbeatClient = nil
        klog.InfoS("Standalone mode, no API client")
    // 如果kubeDeps.KubeClient，kubeDeps.EventClient或kubeDeps.HeartbeatClient为nil
    case kubeDeps.KubeClient == nil, kubeDeps.EventClient == nil, kubeDeps.HeartbeatClient == nil:
        clientConfig, onHeartbeatFailure, err := buildKubeletClientConfig(ctx, s, kubeDeps.TracerProvider, nodeName)
        // 构建kubelet客户端配置
        if err != nil {
            return err
        }
        if onHeartbeatFailure == nil {
            return errors.New("onHeartbeatFailure must be a valid function other than nil")
        }
        kubeDeps.OnHeartbeatFailure = onHeartbeatFailure

        kubeDeps.KubeClient, err = clientset.NewForConfig(clientConfig)
        // 使用客户端配置创建kubelet客户端
        if err != nil {
            return fmt.Errorf("failed to initialize kubelet client: %w", err)
        }

        // 创建用于事件的单独客户端
        eventClientConfig := *clientConfig
        eventClientConfig.QPS = float32(s.EventRecordQPS)
        eventClientConfig.Burst = int(s.EventBurst)
        kubeDeps.EventClient, err = v1core.NewForConfig(&eventClientConfig)
        if err != nil {
            return fmt.Errorf("failed to initialize kubelet event client: %w", err)
        }

        // 创建用于心跳的单独客户端，禁用速率限制并附加超时
        heartbeatClientConfig := *clientConfig
        heartbeatClientConfig.Timeout = s.KubeletConfiguration.NodeStatusUpdateFrequency.Duration
        // 计算超时时间，取节点租约时长和状态更新频率的较小值作为超时时间
		leaseTimeout := time.Duration(s.KubeletConfiguration.NodeLeaseDurationSeconds) * time.Second
		if heartbeatClientConfig.Timeout > leaseTimeout {
			heartbeatClientConfig.Timeout = leaseTimeout
		}
		// 设置心跳客户端的QPS为-1
		heartbeatClientConfig.QPS = float32(-1)
		kubeDeps.HeartbeatClient, err = clientset.NewForConfig(&heartbeatClientConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize kubelet heartbeat client: %w", err)
		}
	}
	// 如果认证组件未初始化，则构建认证组件
	if kubeDeps.Auth == nil {
		auth, runAuthenticatorCAReload, err := BuildAuth(nodeName, kubeDeps.KubeClient, s.KubeletConfiguration)
		if err != nil {
			return err
		}
		kubeDeps.Auth = auth
		runAuthenticatorCAReload(ctx.Done())
	}

	var cgroupRoots []string
    // 根据配置获取节点可分配资源的cgroup路径，并添加到cgroupRoots中
	nodeAllocatableRoot := cm.NodeAllocatableRoot(s.CgroupRoot, s.CgroupsPerQOS, s.CgroupDriver)
	cgroupRoots = append(cgroupRoots, nodeAllocatableRoot)
	kubeletCgroup, err := cm.GetKubeletContainer(s.KubeletCgroups)
	if err != nil {
		klog.InfoS("Failed to get the kubelet's cgroup. Kubelet system container metrics may be missing.", "err", err)
	} else if kubeletCgroup != "" {
        // 如果kubeletCgroup不为空，则将其添加到cgroupRoots中
		cgroupRoots = append(cgroupRoots, kubeletCgroup)
	}

	if s.RuntimeCgroups != "" {
		// RuntimeCgroups是可选的，如果未指定则忽略
		cgroupRoots = append(cgroupRoots, s.RuntimeCgroups)
	}

	if s.SystemCgroups != "" {
		// SystemCgroups是可选的，如果未指定则忽略
		cgroupRoots = append(cgroupRoots, s.SystemCgroups)
	}
	// 如果CAdvisorInterface未初始化，则根据配置创建CAdvisorInterface
	if kubeDeps.CAdvisorInterface == nil {
		imageFsInfoProvider := cadvisor.NewImageFsInfoProvider(s.ContainerRuntimeEndpoint)
		kubeDeps.CAdvisorInterface, err = cadvisor.New(imageFsInfoProvider, s.RootDirectory, cgroupRoots, cadvisor.UsingLegacyCadvisorStats(s.ContainerRuntimeEndpoint), s.LocalStorageCapacityIsolation)
		if err != nil {
			return err
		}
	}

	// 如果需要，设置事件记录器
	makeEventRecorder(kubeDeps, nodeName)
	// 如果ContainerManager未初始化，则根据配置创建ContainerManager
	if kubeDeps.ContainerManager == nil {
		if s.CgroupsPerQOS && s.CgroupRoot == "" {
			klog.InfoS("--cgroups-per-qos enabled, but --cgroup-root was not specified.  defaulting to /")
			s.CgroupRoot = "/"
		}

		machineInfo, err := kubeDeps.CAdvisorInterface.MachineInfo()
		if err != nil {
			return err
		}
		reservedSystemCPUs, err := getReservedCPUs(machineInfo, s.ReservedSystemCPUs)
		if err != nil {
			return err
		}
		if reservedSystemCPUs.Size() > 0 {
			// 在命令行选项验证阶段已经测试了--system-reserved-cgroup或--kube-reserved-cgroup是否已指定，所以覆盖
			klog.InfoS("Option --reserved-cpus is specified, it will overwrite the cpu setting in KubeReserved and SystemReserved", "kubeReservedCPUs", s.KubeReserved, "systemReservedCPUs", s.SystemReserved)
			if s.KubeReserved != nil {
				delete(s.KubeReserved, "cpu")
			}
			if s.SystemReserved == nil {
				s.SystemReserved = make(map[string]string)
			}
			s.SystemReserved["cpu"] = strconv.Itoa(reservedSystemCPUs.Size())
			klog.InfoS("After cpu setting is overwritten", "kubeReservedCPUs", s.KubeReserved, "systemReservedCPUs", s.SystemReserved)
		}

		kubeReserved, err := parseResourceList(s.KubeReserved)
		if err != nil {
			return fmt.Errorf("--kube-reserved value failed to parse: %w", err)
		}
		systemReserved, err := parseResourceList(s.SystemReserved)
		if err != nil {
			return fmt.Errorf("--system-reserved value failed to parse: %w", err)
		}
		var hardEvictionThresholds []evictionapi.Threshold
		// 如果用户请求忽略驱逐阈值，则不在这里设置hardEvictionThresholds的有效值
		if !s.ExperimentalNodeAllocatableIgnoreEvictionThreshold {
			hardEvictionThresholds, err = eviction.ParseThresholdConfig([]string{}, s.EvictionHard, nil, nil, nil)
			if err != nil {
				return err
			}
		}
		experimentalQOSReserved, err := cm.ParseQOSReserved(s.QOSReserved)
		if err != nil {
			return fmt.Errorf("--qos-reserved value failed to parse: %w", err)
		}

		var cpuManagerPolicyOptions map[string]string
		if utilfeature.DefaultFeatureGate.Enabled(features.CPUManagerPolicyOptions) {
			cpuManagerPolicyOptions = s.CPUManagerPolicyOptions
		} else if s.CPUManagerPolicyOptions != nil {
			return fmt.Errorf("CPU Manager policy options %v require feature gates %q, %q enabled",
				s.CPUManagerPolicyOptions, features.CPUManager, features.CPUManagerPolicyOptions)
		}

		var topologyManagerPolicyOptions map[string]string
		if utilfeature.DefaultFeatureGate.Enabled(features.TopologyManagerPolicyOptions) {
			topologyManagerPolicyOptions = s.TopologyManagerPolicyOptions
		} else if s.TopologyManagerPolicyOptions != nil {
			return fmt.Errorf("topology manager policy options %v require feature gates %q enabled",
				s.TopologyManagerPolicyOptions, features.TopologyManagerPolicyOptions)
		}

		kubeDeps.ContainerManager, err = cm.NewContainerManager(
			kubeDeps.Mounter,
			kubeDeps.CAdvisorInterface,
			cm.NodeConfig{
				RuntimeCgroupsName:    s.RuntimeCgroups,
				SystemCgroupsName:     s.SystemCgroups,
				KubeletCgroupsName:    s.KubeletCgroups,
				KubeletOOMScoreAdj:    s.OOMScoreAdj,
				CgroupsPerQOS:         s.CgroupsPerQOS,
				CgroupRoot:            s.CgroupRoot,
				CgroupDriver:          s.CgroupDriver,
				KubeletRootDir:        s.RootDirectory,
				ProtectKernelDefaults: s.ProtectKernelDefaults,
				NodeAllocatableConfig: cm.NodeAllocatableConfig{
					KubeReservedCgroupName:   s.KubeReservedCgroup,
					SystemReservedCgroupName: s.SystemReservedCgroup,
					EnforceNodeAllocatable:   sets.NewString(s.EnforceNodeAllocatable...),
					KubeReserved:             kubeReserved,
					SystemReserved:           systemReserved,
					ReservedSystemCPUs:       reservedSystemCPUs,
					HardEvictionThresholds:   hardEvictionThresholds,
				},
				QOSReserved:                              *experimentalQOSReserved,
				CPUManagerPolicy:                         s.CPUManagerPolicy,
				CPUManagerPolicyOptions:                  cpuManagerPolicyOptions,
				CPUManagerReconcilePeriod:                s.CPUManagerReconcilePeriod.Duration,
				ExperimentalMemoryManagerPolicy:          s.MemoryManagerPolicy,
				ExperimentalMemoryManagerReservedMemory:  s.ReservedMemory,
				PodPidsLimit:                             s.PodPidsLimit,
				EnforceCPULimits:                         s.CPUCFSQuota,
				CPUCFSQuotaPeriod:                        s.CPUCFSQuotaPeriod.Duration,
				TopologyManagerPolicy:                    s.TopologyManagerPolicy,
				TopologyManagerScope:                     s.TopologyManagerScope,
				ExperimentalTopologyManagerPolicyOptions: topologyManagerPolicyOptions,
			},
			s.FailSwapOn,
			kubeDeps.Recorder,
			kubeDeps.KubeClient,
		)

		if err != nil {
			return err
		}
	}

	if kubeDeps.PodStartupLatencyTracker == nil {
		kubeDeps.PodStartupLatencyTracker = kubeletutil.NewPodStartupLatencyTracker()
	}

	// TODO(vmarmol): 通过容器配置完成此操作。
	oomAdjuster := kubeDeps.OOMAdjuster
	if err := oomAdjuster.ApplyOOMScoreAdj(0, int(s.OOMScoreAdj)); err != nil {
		klog.InfoS("Failed to ApplyOOMScoreAdj", "err", err)
	}

	err = kubelet.PreInitRuntimeService(&s.KubeletConfiguration, kubeDeps)
	if err != nil {
		return err
	}

	if err := RunKubelet(s, kubeDeps, s.RunOnce); err != nil {
		return err
	}

	if s.HealthzPort > 0 {
		mux := http.NewServeMux()
		healthz.InstallHandler(mux)
		go wait.Until(func() {
			err := http.ListenAndServe(net.JoinHostPort(s.HealthzBindAddress, strconv.Itoa(int(s.HealthzPort))), mux)
			if err != nil {
				klog.ErrorS(err, "Failed to start healthz server")
			}
		}, 5*time.Second, wait.NeverStop)
	}

	if s.RunOnce {
		return nil
	}

	// 如果使用systemd，通知它我们已经启动
	go daemon.SdNotify(false, "READY=1")

	select {
	case <-done:
		break
	case <-ctx.Done():
		break
	}

	return nil
}
```

