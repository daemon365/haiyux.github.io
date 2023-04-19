---
title: "kube-scheduler 启动逻辑代码走读"
subtitle:
date: 2023-04-17T21:15:59+08:00
draft: false
toc: true
categories: 
  - cloud
tags: 
  - kubernetes
  - controller
authors:
    - haiyux
# featuredImagePreview: /img/preview/controller/attachdetach-controller.jpg
---

## 介绍

Kube-scheduler是Kubernetes中的一个组件，用于将新的Pod调度到集群中的合适节点上。它监视集群中新创建的Pod，并根据指定的调度策略将其分配给可用的节点。Kube-scheduler可以自动识别节点的资源使用情况和可用性，并将Pod调度到具有足够资源的节点上，以确保Pod的高可用性和性能。

Kube-scheduler的工作流程如下：

1. Kube-scheduler通过API Server监听新创建的Pod。
2. Kube-scheduler检查每个Pod的调度要求（例如资源需求和亲和性要求）。
3. Kube-scheduler将Pod与可用的节点进行匹配。
4. Kube-scheduler选择最佳节点，并将Pod绑定到该节点上。
5. Kube-scheduler向API Server发送调度结果，将Pod的绑定信息更新到etcd中。

Kube-scheduler可以配置多种调度策略，例如默认的策略、亲和性和反亲和性策略、节点亲和性和反亲和性策略、Pod亲和性和反亲和性策略等，以适应不同的应用场景。

代码位置：`https://github.com/kubernetes/kubernetes/blob/master/cmd/kube-scheduler`

## 启动函数

```go
func main() {
	command := app.NewSchedulerCommand()
	code := cli.Run(command)
	os.Exit(code)
}
```

`app.NewSchedulerCommand()` 函数返回一个 `cmd *cobra.Command` 对象，该对象是一个命令行参数的集合。这个对象可以让你将命令绑定到其中，以便在启动时接受各种参数。

`cmd *cobra.Command` 对象来源于 `spf13/cobra` 包，这个包是一个用于现代 Go CLI 交互的命令行工具。使用 `cmd *cobra.Command` 对象，你可以轻松地将命令行参数集成到你的应用程序中，以方便用户在启动时配置应用程序的各种选项。

在实际应用程序中，你可以将 `cmd *cobra.Command` 对象与其他应用程序逻辑相结合，以便在运行时自动执行一些操作，例如根据命令行参数初始化应用程序的配置等。这个功能非常有用，特别是当你需要在应用程序启动时进行一些特殊处理时。

`cli.Run(command)` 是一个自定义函数，它的作用是启动 `cmd *cobra.Command` 对象并执行其中的命令行参数。在这之前，它还可以进行一些初始化操作，例如初始化日志、设置日志级别、设置日志格式等。这些操作可以确保应用程序在启动时能够正确地记录日志，并且可以方便地进行故障排除和调试。

## NewSchedulerCommand

```GO
func NewSchedulerCommand(registryOptions ...Option) *cobra.Command {
	opts := options.NewOptions() // 创建一个新的 Options 实例

	cmd := &cobra.Command{ // 创建一个 cobra.Command 实例
		Use: "kube-scheduler", // 设置命令的使用说明
		Long: `The Kubernetes scheduler is a control plane process which assigns
Pods to Nodes. The scheduler determines which Nodes are valid placements for
each Pod in the scheduling queue according to constraints and available
resources. The scheduler then ranks each valid Node and binds the Pod to a
suitable Node. Multiple different schedulers may be used within a cluster;
kube-scheduler is the reference implementation.
See [scheduling](https://kubernetes.io/docs/concepts/scheduling-eviction/)
for more information about scheduling and the kube-scheduler component.`, // 设置命令的详细说明
		RunE: func(cmd *cobra.Command, args []string) error { // 设置命令的运行函数
			return runCommand(cmd, opts, registryOptions...) // 调用 runCommand 函数并传入参数
		},
		Args: func(cmd *cobra.Command, args []string) error { // 设置命令的参数验证函数
			for _, arg := range args {
				if len(arg) > 0 {
					return fmt.Errorf("%q does not take any arguments, got %q", cmd.CommandPath(), args)
				}
			}
			return nil
		},
	}

	nfs := opts.Flags // 获取 Options 实例的 Flags
	verflag.AddFlags(nfs.FlagSet("global")) // 添加全局标志到 Flags
	globalflag.AddGlobalFlags(nfs.FlagSet("global"), cmd.Name(), logs.SkipLoggingConfigurationFlags()) // 添加全局标志到 Flags
	fs := cmd.Flags() // 获取命令的 Flags
	for _, f := range nfs.FlagSets { // 遍历 Options 实例的 FlagSets
		fs.AddFlagSet(f) // 将 FlagSet 添加到命令的 Flags
	}

	cols, _, _ := term.TerminalSize(cmd.OutOrStdout()) // 获取终端的大小
	cliflag.SetUsageAndHelpFunc(cmd, *nfs, cols) // 设置命令的使用和帮助函数

	if err := cmd.MarkFlagFilename("config", "yaml", "yml", "json"); err != nil { // 给命令的 "config" 标志设置文件名后缀限制
		klog.Background().Error(err, "Failed to mark flag filename")
	}

	return cmd // 返回创建的命令实例
}
```

### Options

- Options是一些一些参数

```GO
type Options struct {
	// 默认值。
	ComponentConfig *kubeschedulerconfig.KubeSchedulerConfiguration // 组件配置

	SecureServing  *apiserveroptions.SecureServingOptionsWithLoopback // 安全服务选项
	Authentication *apiserveroptions.DelegatingAuthenticationOptions // 委托认证选项
	Authorization  *apiserveroptions.DelegatingAuthorizationOptions  // 委托授权选项
	Metrics        *metrics.Options // 指标选项
	Logs           *logs.Options // 日志选项
	Deprecated     *DeprecatedOptions // 弃用选项
	LeaderElection *componentbaseconfig.LeaderElectionConfiguration // 领导选举配置

	ConfigFile string // scheduler 服务器的配置文件路径
	WriteConfigTo string // 默认配置将被写入的路径

	Master string // Kubernetes API Server 的地址

	Flags *cliflag.NamedFlagSets // 解析后的 CLI 标志
}
```

### runCommand

```GO
func runCommand(cmd *cobra.Command, opts *options.Options, registryOptions ...Option) error {
	verflag.PrintAndExitIfRequested() // 如果命令行参数中包含版本信息相关的标志，则打印版本信息并退出

	// 在日志配置生效之前，尽早地激活日志记录，并显示带有最终日志配置的标志。
	if err := logsapi.ValidateAndApply(opts.Logs, utilfeature.DefaultFeatureGate); err != nil { // 校验并应用日志配置，如果出错则打印错误信息并退出
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	cliflag.PrintFlags(cmd.Flags()) // 打印命令行标志

	ctx, cancel := context.WithCancel(context.Background()) // 创建一个带有取消功能的上下文
	defer cancel() // 在函数返回前调用取消函数，确保资源被释放

	go func() {
		stopCh := server.SetupSignalHandler() // 设置信号处理器
		<-stopCh // 等待信号处理器接收到停止信号
		cancel() // 调用取消函数以取消上下文
	}()

	cc, sched, err := Setup(ctx, opts, registryOptions...) // 调用Setup函数设置运行环境
	if err != nil {
		return err // 如果设置过程中出错，则返回错误
	}

	utilfeature.DefaultMutableFeatureGate.AddMetrics() // 添加功能启用度量

	return Run(ctx, cc, sched) // 调用Run函数运行程序
}
```

#### Setup

```GO
func Setup(ctx context.Context, opts *options.Options, outOfTreeRegistryOptions ...Option) (*schedulerserverconfig.CompletedConfig, *scheduler.Scheduler, error) {
	if cfg, err := latest.Default(); err != nil { // 获取最新的默认配置
		return nil, nil, err // 如果获取失败，则返回错误
	} else {
		opts.ComponentConfig = cfg // 将获取到的默认配置设置为组件配置选项中的配置
	}

	if errs := opts.Validate(); len(errs) > 0 { // 验证组件配置选项的有效性
		return nil, nil, utilerrors.NewAggregate(errs) // 如果验证失败，则返回错误
	}

	c, err := opts.Config(ctx) // 根据组件配置选项创建配置
	if err != nil {
		return nil, nil, err // 如果创建配置失败，则返回错误
	}

	// 获取完整的配置
	cc := c.Complete()

	outOfTreeRegistry := make(runtime.Registry) // 创建一个新的外部注册表
	for _, option := range outOfTreeRegistryOptions { // 遍历外部注册表选项
		if err := option(outOfTreeRegistry); err != nil { // 如果调用外部注册表选项时出错，则返回错误
			return nil, nil, err
		}
	}

	recorderFactory := getRecorderFactory(&cc) // 获取事件记录器工厂
	completedProfiles := make([]kubeschedulerconfig.KubeSchedulerProfile, 0) // 创建一个空的已完成的配置文件切片

	// 创建调度器
	sched, err := scheduler.New(cc.Client,
		cc.InformerFactory,
		cc.DynInformerFactory,
		recorderFactory,
		ctx.Done(),
		scheduler.WithComponentConfigVersion(cc.ComponentConfig.TypeMeta.APIVersion),
		scheduler.WithKubeConfig(cc.KubeConfig),
		scheduler.WithProfiles(cc.ComponentConfig.Profiles...),
		scheduler.WithPercentageOfNodesToScore(cc.ComponentConfig.PercentageOfNodesToScore),
		scheduler.WithFrameworkOutOfTreeRegistry(outOfTreeRegistry),
		scheduler.WithPodMaxBackoffSeconds(cc.ComponentConfig.PodMaxBackoffSeconds),
		scheduler.WithPodInitialBackoffSeconds(cc.ComponentConfig.PodInitialBackoffSeconds),
		scheduler.WithPodMaxInUnschedulablePodsDuration(cc.PodMaxInUnschedulablePodsDuration),
		scheduler.WithExtenders(cc.ComponentConfig.Extenders...),
		scheduler.WithParallelism(cc.ComponentConfig.Parallelism),
		scheduler.WithBuildFrameworkCapturer(func(profile kubeschedulerconfig.KubeSchedulerProfile) {
			// 在Framework实例化期间处理配置文件以设置默认插件和配置项，将其捕获用于日志记录
			completedProfiles = append(completedProfiles, profile)
		}),
	)
	if err != nil {
		return nil, nil, err // 如果创建调度器失败，则返回错误
	}
	if err := options.LogOrWriteConfig(klog.FromContext(ctx), opts.WriteConfigTo, &cc.ComponentConfig, completedProfiles); err != nil {
		return nil, nil, err // 如果记录或写入配置时出错，则返回错误
	}

	return &cc, sched, nil // 返回完整的配置、调度器和空错误
}
```

##### Complete

```GO
func (c *Config) Complete() CompletedConfig {
	cc := completedConfig{c}

	apiserver.AuthorizeClientBearerToken(c.LoopbackClientConfig, &c.Authentication, &c.Authorization)

	return CompletedConfig{&cc}
}

type completedConfig struct {
	*Config
}

type Config struct {
	// 调度器服务器的配置对象
	ComponentConfig kubeschedulerconfig.KubeSchedulerConfiguration

	// ：用于特权回环连接的配置信息
	LoopbackClientConfig *restclient.Config

	Authentication apiserver.AuthenticationInfo
	Authorization  apiserver.AuthorizationInfo
	SecureServing  *apiserver.SecureServingInfo

	Client             clientset.Interface
	KubeConfig         *restclient.Config
	InformerFactory    informers.SharedInformerFactory
	DynInformerFactory dynamicinformer.DynamicSharedInformerFactory

	//nolint:staticcheck // SA1019 this deprecated field still needs to be used for now. It will be removed once the migration is done.
	EventBroadcaster events.EventBroadcasterAdapter

	// LeaderElection is optional.
	LeaderElection *leaderelection.LeaderElectionConfig

	// Pod在不可调度队列中最大的停留时间。如果Pod在不可调度队列中停留的时间超过这个值，将会被移到backoff队列或active队列中。
    // 如果这个值为空，将使用默认值（5分钟），类型为time.Duration。
	PodMaxInUnschedulablePodsDuration time.Duration
}
```

#### Run

```go
func Run(ctx context.Context, cc *schedulerserverconfig.CompletedConfig, sched *scheduler.Scheduler) error {
	logger := klog.FromContext(ctx)

	// To help debugging, immediately log version
	logger.Info("Starting Kubernetes Scheduler", "version", version.Get())

	logger.Info("Golang settings", "GOGC", os.Getenv("GOGC"), "GOMAXPROCS", os.Getenv("GOMAXPROCS"), "GOTRACEBACK", os.Getenv("GOTRACEBACK"))

	// Configz registration.
	// 注册 Configz，用于配置信息的管理和展示
	if cz, err := configz.New("componentconfig"); err == nil {
		cz.Set(cc.ComponentConfig)
	} else {
		return fmt.Errorf("unable to register configz: %s", err)
	}

	// Start events processing pipeline.
	// 启动事件处理流程
	cc.EventBroadcaster.StartRecordingToSink(ctx.Done())
	defer cc.EventBroadcaster.Shutdown()

	// Setup healthz checks.
	// 设置健康检查
	var checks []healthz.HealthChecker
	if cc.ComponentConfig.LeaderElection.LeaderElect {
		checks = append(checks, cc.LeaderElection.WatchDog)
	}

	waitingForLeader := make(chan struct{})
	isLeader := func() bool {
		select {
		case _, ok := <-waitingForLeader:
			// if channel is closed, we are leading
			return !ok
		default:
			// channel is open, we are waiting for a leader
			return false
		}
	}

	// Start up the healthz server.
	// 启动健康检查服务器
	if cc.SecureServing != nil {
		handler := buildHandlerChain(newHealthzAndMetricsHandler(&cc.ComponentConfig, cc.InformerFactory, isLeader, checks...), cc.Authentication.Authenticator, cc.Authorization.Authorizer)
		// TODO: handle stoppedCh and listenerStoppedCh returned by c.SecureServing.Serve
		if _, _, err := cc.SecureServing.Serve(handler, 0, ctx.Done()); err != nil {
			// fail early for secure handlers, removing the old error loop from above
			return fmt.Errorf("failed to start secure server: %v", err)
		}
	}

	// Start all informers.
	// 启动所有 informer
	cc.InformerFactory.Start(ctx.Done())
	// DynInformerFactory can be nil in tests.
	if cc.DynInformerFactory != nil {
		cc.DynInformerFactory.Start(ctx.Done())
	}

	// Wait for all caches to sync before scheduling.
	// 在调度之前等待所有缓存同步
	cc.InformerFactory.WaitForCacheSync(ctx.Done())
	// DynInformerFactory can be nil in tests.
	if cc.DynInformerFactory != nil {
		cc.DynInformerFactory.WaitForCacheSync(ctx.Done())
	}

	// If leader election is enabled, runCommand via LeaderElector until done and exit.
	// 如果启用了 leader 选举，则通过 LeaderElector 运行命令，直到完成并退出
	if cc.LeaderElection != nil {
		cc.LeaderElection.Callbacks = leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				close(waitingForLeader)
				sched.Run(ctx)
			},
            // OnStoppedLeading 是 LeaderCallbacks 接口的实现函数，在失去 leader 角色时调用
			// 根据情况选择是否终止程序或者进行错误处理
			OnStoppedLeading: func() {
				select {
				case <-ctx.Done():
					// 如果收到终止信号，则退出程序并返回状态码 0
					logger.Info("Requested to terminate, exiting")
					os.Exit(0)
				default:
					// 如果失去了 leader 角色，则记录错误信息并调用 klog.FlushAndExit 终止程序
					logger.Error(nil, "Leaderelection lost")
					klog.FlushAndExit(klog.ExitFlushTimeout, 1)
				}
			},
		}
        // 创建 LeaderElector 实例，并通过 Run 方法开始进行 leader 选举
		leaderElector, err := leaderelection.NewLeaderElector(*cc.LeaderElection)
		if err != nil {
			return fmt.Errorf("couldn't create leader elector: %v", err)
		}

		leaderElector.Run(ctx)

		return fmt.Errorf("lost lease")
	}

	// 如果禁用了 leader 选举，则直接执行 sched.Run(ctx) 函数进行任务调度
	// 返回错误信息 "finished without leader elect"
	close(waitingForLeader)
	sched.Run(ctx)
	return fmt.Errorf("finished without leader elect")
}
```

## Scheduler

```go
type Scheduler struct {
	// Cache 用于存储节点和 Pod 的缓存，NodeLister 和 Algorithm 可以观察到 Cache 的变化。
	Cache internalcache.Cache

	// Extenders 是一组用于调度扩展的接口。
    Extenders []framework.Extender

    // NextPod 是一个函数，用于阻塞直到下一个 Pod 可用。
    // 我们不使用 channel 是因为调度一个 Pod 可能需要一些时间，
    // 我们不希望在 channel 中等待的期间 Pod 变得过期。
    NextPod func() *framework.QueuedPodInfo

    // FailureHandler 是在调度失败时调用的处理函数。
    FailureHandler FailureHandlerFn

    // SchedulePod 尝试将给定的 Pod 调度到节点列表中的某个节点。
    // 在成功时返回一个 ScheduleResult 结构体，其中包含建议的主机名称，
    // 否则返回一个带有失败原因的 FitError。
    SchedulePod func(ctx context.Context, fwk framework.Framework, state *framework.CycleState, pod *v1.Pod) (ScheduleResult, error)

    // StopEverything 是一个通道，用于关闭调度器。
    StopEverything <-chan struct{}

    // SchedulingQueue 用于存储待调度的 Pod。
    SchedulingQueue internalqueue.SchedulingQueue

    // Profiles 是调度器的调度配置文件。
    Profiles profile.Map

    client clientset.Interface

    // nodeInfoSnapshot 是节点信息的快照。
    nodeInfoSnapshot *internalcache.Snapshot

    // percentageOfNodesToScore 是用于评分的节点百分比。
    percentageOfNodesToScore int32

    // nextStartNodeIndex 是下一个开始评分的节点索引。
    nextStartNodeIndex int
}

type ScheduleResult struct {
	// 被选中节点的名称。
	SuggestedHost string // 被调度器选择用于运行该 pod 的节点的名称
	// 在过滤阶段及之后，调度器评估了多少个节点。
	EvaluatedNodes int // 调度器评估该 pod 时考虑的节点数目
	// 在评估的节点中有多少个节点适合运行该 pod。
	FeasibleNodes int // 在所有评估的节点中，有多少个节点符合该 pod 的需求
	// 调度循环的提名信息。
	nominatingInfo *framework.NominatingInfo // 调度循环期间使用的提名信息
}
```

### Options

```go
type schedulerOptions struct {
	componentConfigVersion string       // 调度器组件的配置版本
	kubeConfig             *restclient.Config // Kubernetes API Server 的配置信息
	// 在 v1 中，如果 profile 级别设置了 percentageOfNodesToScore，则会覆盖此处设置。
	percentageOfNodesToScore int32 // 用于计算每个节点的资源得分的 pod 占总 pod 数量的百分比
	podInitialBackoffSeconds int64 // 用于计算 pod 调度失败后第一次重试等待的秒数
	podMaxBackoffSeconds     int64 // 用于计算 pod 调度失败后最多重试等待的秒数
	podMaxInUnschedulablePodsDuration time.Duration // 未能调度的 pod 最长的持续时间
	// 包含与 in-tree 注册表合并的 out-of-tree 插件。
	frameworkOutOfTreeRegistry frameworkruntime.Registry // 调度器的插件注册表
	profiles                   []schedulerapi.KubeSchedulerProfile // 调度器配置文件
	extenders                  []schedulerapi.Extender // 扩展器列表
	frameworkCapturer          FrameworkCapturer // 用于捕获调度过程中的信息
	parallelism                int32 // 调度器并行处理的任务数
	applyDefaultProfile        bool // 是否使用默认的调度器配置文件
}

type Option func(*schedulerOptions)
```


### New

```go
func New(client clientset.Interface, // 用于与 Kubernetes API Server 通信的客户端接口
	informerFactory informers.SharedInformerFactory, // Kubernetes Informer 工厂
	dynInformerFactory dynamicinformer.DynamicSharedInformerFactory, // Kubernetes DynamicInformer 工厂
	recorderFactory profile.RecorderFactory, // 用于创建事件记录器的工厂
	stopCh <-chan struct{}, // 用于停止调度器的通道，由外部传入
	opts ...Option) (*Scheduler, error) { // 可选的调度器选项，返回调度器实例和错误

	// 如果停止通道为空，则使用 wait.NeverStop 作为默认值
	stopEverything := stopCh
	if stopEverything == nil {
		stopEverything = wait.NeverStop
	}

	// 设置调度器选项
	options := defaultSchedulerOptions
	for _, opt := range opts {
		opt(&options)
	}

	// 如果设置了应用默认配置文件，则使用默认配置文件
	if options.applyDefaultProfile {
		var versionedCfg configv1.KubeSchedulerConfiguration
		scheme.Scheme.Default(&versionedCfg)
		cfg := schedulerapi.KubeSchedulerConfiguration{}
		if err := scheme.Scheme.Convert(&versionedCfg, &cfg, nil); err != nil {
			return nil, err
		}
		options.profiles = cfg.Profiles
	}

	// 创建 InTreeRegistry，并合并 FrameworkOutOfTreeRegistry
	registry := frameworkplugins.NewInTreeRegistry()
	if err := registry.Merge(options.frameworkOutOfTreeRegistry); err != nil {
		return nil, err
	}

	// 注册度量指标
	metrics.Register()

	// 构建 Extender
	extenders, err := buildExtenders(options.extenders, options.profiles)
	if err != nil {
		return nil, fmt.Errorf("couldn't build extenders: %w", err)
	}

	// 获取 PodLister 和 NodeLister
	podLister := informerFactory.Core().V1().Pods().Lister()
	nodeLister := informerFactory.Core().V1().Nodes().Lister()

	// 创建 Snapshot 和 ClusterEventMap，并获取 MetricsRecorder
	snapshot := internalcache.NewEmptySnapshot()
	clusterEventMap := make(map[framework.ClusterEvent]sets.Set[string])
	metricsRecorder := metrics.NewMetricsAsyncRecorder(1000, time.Second, stopCh)

	// 创建 Profiles
	profiles, err := profile.NewMap(options.profiles, registry, recorderFactory, stopCh,
		frameworkruntime.WithComponentConfigVersion(options.componentConfigVersion),
		frameworkruntime.WithClientSet(client),
		frameworkruntime.WithKubeConfig(options.kubeConfig),
		frameworkruntime.WithInformerFactory(informerFactory),
		frameworkruntime.WithSnapshotSharedLister(snapshot),
		frameworkruntime.WithCaptureProfile(frameworkruntime.CaptureProfile(options.frameworkCapturer)),
		frameworkruntime.WithClusterEventMap(clusterEventMap),
		frameworkruntime.WithParallelism(int(options.parallelism)),
		frameworkruntime.WithExtenders(extenders),
		frameworkruntime.WithMetricsRecorder(metricsRecorder),
	)
	if err != nil {
		return nil, fmt.Errorf("initializing profiles: %v", err)
	}

	// 如果没有 Profile 则返回错误
	if len(profiles) == 0 {
		return nil, errors.New("at least one profile is required")
	}

	// 创建一个名为 preEnqueuePluginMap 的 map，用于存储预处理插件（PreEnqueuePlugin）
	preEnqueuePluginMap := make(map[string][]framework.PreEnqueuePlugin)
    // 遍历 profiles 的每个元素，其中 profileName 是 key，profile 是 value
	for profileName, profile := range profiles {
         // 将 profile 的 PreEnqueuePlugins() 返回值存储到 preEnqueuePluginMap 中，使用 profileName 作为 key
		preEnqueuePluginMap[profileName] = profile.PreEnqueuePlugins()
	}
	// 使用 NewSchedulingQueue() 函数创建一个名为 podQueue 的 SchedulingQueue 对象，同时传入一系列参数
    podQueue := internalqueue.NewSchedulingQueue(
        // 使用 options.profiles[0].SchedulerName 所对应的 profile 的 QueueSortFunc() 作为排序函数
        profiles[options.profiles[0].SchedulerName].QueueSortFunc(),
        // 传入 informerFactory 对象
        informerFactory,
        // 传入 WithPodInitialBackoffDuration() 函数返回的选项，使用 options.podInitialBackoffSeconds 作为初始 backoff 时间
        	internalqueue.WithPodInitialBackoffDuration(time.Duration(options.podInitialBackoffSeconds)*time.Second),
        // 传入 WithPodMaxBackoffDuration() 函数返回的选项，使用 options.podMaxBackoffSeconds 作为最大 backoff 时间
        internalqueue.WithPodMaxBackoffDuration(time.Duration(options.podMaxBackoffSeconds)*time.Second),
        // 传入 WithPodLister() 函数返回的选项，使用 podLister 对象作为 podLister
        internalqueue.WithPodLister(podLister),
        // 传入 WithClusterEventMap() 函数返回的选项，使用 clusterEventMap 对象作为 clusterEventMap
        internalqueue.WithClusterEventMap(clusterEventMap),
        // 传入 WithPodMaxInUnschedulablePodsDuration() 函数返回的选项，使用 options.podMaxInUnschedulablePodsDuration 作为最大等待时间
        internalqueue.WithPodMaxInUnschedulablePodsDuration(options.podMaxInUnschedulablePodsDuration),
        // 传入 WithPreEnqueuePluginMap() 函数返回的选项，使用 preEnqueuePluginMap 对象作为 preEnqueuePluginMap
        internalqueue.WithPreEnqueuePluginMap(preEnqueuePluginMap),
        // 传入 WithPluginMetricsSamplePercent() 函数返回的选项，使用 pluginMetricsSamplePercent 作为样本采集比例
        internalqueue.WithPluginMetricsSamplePercent(pluginMetricsSamplePercent),
        // 传入 WithMetricsRecorder() 函数返回的选项，使用 metricsRecorder 对象作为 metricsRecorder
        internalqueue.WithMetricsRecorder(*metricsRecorder),
    )

    // 遍历 profiles 中的每个元素，其中 fwk 是 value
    for _, fwk := range profiles {
        // 将 podQueue 设置为 fwk 的 PodNominator
        fwk.SetPodNominator(podQueue)
    }
	
    // 使用 New() 函数创建一个名为 schedulerCache 的 Cache 对象，使用 durationToExpireAssumedPod 作为缓存过期时间，stopEverything 作为 stopCh
	schedulerCache := internalcache.New(durationToExpireAssumedPod, stopEverything)

	// 设置缓存调试器
	debugger := cachedebugger.New(nodeLister, podLister, schedulerCache, podQueue)
	debugger.ListenForSignal(stopEverything)
	// 创建一个调度器实例
	sched := &Scheduler{
		Cache:                    schedulerCache,
		client:                   client,
		nodeInfoSnapshot:         snapshot,
		percentageOfNodesToScore: options.percentageOfNodesToScore,
		Extenders:                extenders,
		NextPod:                  internalqueue.MakeNextPodFunc(podQueue),
		StopEverything:           stopEverything,
		SchedulingQueue:          podQueue,
		Profiles:                 profiles,
	}
    // 应用默认的处理程序
	sched.applyDefaultHandlers()
	// 添加所有事件处理程序
	addAllEventHandlers(sched, informerFactory, dynInformerFactory, unionedGVKs(clusterEventMap))

	return sched, nil
}
```

#### Registry

```go
type Registry map[string]PluginFactory

// PluginFactory is a function that builds a plugin.
type PluginFactory = func(configuration runtime.Object, f framework.Handle) (framework.Plugin, error)

// PluginFactoryWithFts is a function that builds a plugin with certain feature gates.
type PluginFactoryWithFts func(runtime.Object, framework.Handle, plfeature.Features) (framework.Plugin, error)
```

```go
func (r Registry) Register(name string, factory PluginFactory) error {
	if _, ok := r[name]; ok {
		return fmt.Errorf("a plugin named %v already exists", name)
	}
	r[name] = factory
	return nil
}

func (r Registry) Unregister(name string) error {
	if _, ok := r[name]; !ok {
		return fmt.Errorf("no plugin named %v exists", name)
	}
	delete(r, name)
	return nil
}

func (r Registry) Merge(in Registry) error {
	for name, factory := range in {
		if err := r.Register(name, factory); err != nil {
			return err
		}
	}
	return nil
}
```

#### schedulerOptions

```go
type schedulerOptions struct {
    // 组件配置版本
	componentConfigVersion string
    // 表示 Kubernetes 集群的配置
	kubeConfig             *restclient.Config
	// 表示节点评分的百分比，可以被 v1 版本中的 profile 级别的 percentageOfNodesToScore 字段覆盖。
	percentageOfNodesToScore          int32
    //  Pod 初始回退等待的秒数
	podInitialBackoffSeconds          int64
    // 表示 Pod 最大回退等待的秒数
	podMaxBackoffSeconds              int64
    // 表示在不可调度的 Pod 中最大等待的时间
	podMaxInUnschedulablePodsDuration time.Duration
	// 表示外部注册表中的自定义调度器插件，将与内部的注册表合并
	frameworkOutOfTreeRegistry frameworkruntime.Registry
    // 存储调度器的配置文件
	profiles                   []schedulerapi.KubeSchedulerProfile
    // 存储调度器的扩展插件
	extenders                  []schedulerapi.Extender
    // 捕获调度器的状态信息
	frameworkCapturer          FrameworkCapturer
    // 表示调度器的并行度
	parallelism                int32
    // 是否应用默认的调度器配置文件
	applyDefaultProfile        bool
}

var defaultSchedulerOptions = schedulerOptions{
	percentageOfNodesToScore:          schedulerapi.DefaultPercentageOfNodesToScore,
	podInitialBackoffSeconds:          int64(internalqueue.DefaultPodInitialBackoffDuration.Seconds()),
	podMaxBackoffSeconds:              int64(internalqueue.DefaultPodMaxBackoffDuration.Seconds()),
	podMaxInUnschedulablePodsDuration: internalqueue.DefaultPodMaxInUnschedulablePodsDuration,
	parallelism:                       int32(parallelize.DefaultParallelism),
	//理想情况下，我们会在这里静态设置默认配置文件，但我们不能，因为
    //创建默认配置文件可能需要测试功能门，这可能会
    //在测试中动态设置。因此，我们推迟创建它，直到New
    //已调用。
	applyDefaultProfile: true,
}

```

##### KubeSchedulerProfile

```go
type KubeSchedulerProfile struct {
	// 调度器的名称，与该配置文件关联。如果 pod 的 spec.schedulerName 与该字段匹配，则该 pod 将使用此配置文件进行调度。
	SchedulerName string

	// 对于所有找到的可行节点的百分比，调度器在找到一定数量的可行节点后停止在集群中继续查找可行节点，以提高性能。
    // 调度器始终尝试找到至少 "minFeasibleNodesToFind" 个可行节点，无论此标志的值如何。
    // 例如，如果集群大小为 500 个节点，此字段的值为 30，则调度器在找到 150 个可行节点后停止查找更多的可行节点。
    // 当该值为 0 时，将使用默认百分比（根据集群大小在 5% 到 50% 之间）。如果该字段为空，将使用全局的 PercentageOfNodesToScore。
	PercentageOfNodesToScore *int32

	// 指定应启用或禁用的插件集合。启用的插件是除了默认插件之外应启用的插件。禁用的插件是默认插件中应禁用的插件。
    // 对于某个扩展点未指定启用或禁用的插件时，将使用默认插件（如果有）。
    // 如果指定了 QueueSort 插件，则必须为所有配置文件指定相同的 QueueSort 插件和 PluginConfig。
	Plugins *Plugins

	// 每个插件的自定义配置参数的可选集合。对于未指定插件的配置参数，将使用该插件的默认配置。
	PluginConfig []PluginConfig
}

type PluginConfig struct {
	Name string
	Args runtime.Object
}
```

##### Plugins

```go
type Plugins struct {
	// PreEnqueue 是在将 Pod 添加到调度队列之前应该调用的插件列表。
	PreEnqueue PluginSet

	// QueueSort 是在对调度队列中的 Pod 进行排序时应该调用的插件列表。
    QueueSort PluginSet

    // PreFilter 是在调度框架的 "PreFilter" 扩展点处应该调用的插件列表。
    PreFilter PluginSet

    // Filter 是在筛选出无法运行 Pod 的节点时应该调用的插件列表。
    Filter PluginSet

    // PostFilter 是在筛选阶段后，但仅在未找到适合 Pod 的节点时调用的插件列表。
    PostFilter PluginSet

    // PreScore 是在评分之前应该调用的插件列表。
    PreScore PluginSet

    // Score 是在经过筛选阶段后，对节点进行排名时应该调用的插件列表。
    Score PluginSet

    // Reserve 是在将节点分配给运行 Pod 后，调用的保留/取消保留资源的插件列表。
    Reserve PluginSet

    // Permit 是控制 Pod 绑定的插件列表。这些插件可以阻止或延迟 Pod 的绑定。
    Permit PluginSet

    // PreBind 是在 Pod 绑定之前应该调用的插件列表。
    PreBind PluginSet

    // Bind 是在调度框架的 "Bind" 扩展点处应该调用的插件列表。
    // 调度器会按顺序调用这些插件。一旦其中一个插件返回成功，调度器将跳过后续插件的调用。
    Bind PluginSet

    // PostBind 是在 Pod 成功绑定后应该调用的插件列表。
    PostBind PluginSet

    // MultiPoint 是一个简化的配置字段，用于启用所有有效的扩展点的插件。
    MultiPoint PluginSet
}

type PluginSet struct {
	// Enabled specifies plugins that should be enabled in addition to default plugins.
	// These are called after default plugins and in the same order specified here.
	Enabled []Plugin
	// Disabled specifies default plugins that should be disabled.
	// When all default plugins need to be disabled, an array containing only one "*" should be provided.
	Disabled []Plugin
}
```





#### NewInTreeRegistry

```go
// 定义了一个名为NewInTreeRegistry的函数，返回一个类型为runtime.Registry的对象。
func NewInTreeRegistry() runtime.Registry {
	// 定义一个名为fts的plfeature.Features类型的变量
	fts := plfeature.Features{
        // 根据feature gate的状态，启用或禁用相应的特性
		EnableDynamicResourceAllocation:              feature.DefaultFeatureGate.Enabled(features.DynamicResourceAllocation),
		EnableReadWriteOncePod:                       feature.DefaultFeatureGate.Enabled(features.ReadWriteOncePod),
		EnableVolumeCapacityPriority:                 feature.DefaultFeatureGate.Enabled(features.VolumeCapacityPriority),
		EnableMinDomainsInPodTopologySpread:          feature.DefaultFeatureGate.Enabled(features.MinDomainsInPodTopologySpread),
		EnableNodeInclusionPolicyInPodTopologySpread: feature.DefaultFeatureGate.Enabled(features.NodeInclusionPolicyInPodTopologySpread),
		EnableMatchLabelKeysInPodTopologySpread:      feature.DefaultFeatureGate.Enabled(features.MatchLabelKeysInPodTopologySpread),
		EnablePodSchedulingReadiness:                 feature.DefaultFeatureGate.Enabled(features.PodSchedulingReadiness),
		EnablePodDisruptionConditions:                feature.DefaultFeatureGate.Enabled(features.PodDisruptionConditions),
		EnableInPlacePodVerticalScaling:              feature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScaling),
	}
	
    // 定义一个名为registry的runtime.Registry类型的变量
	registry := runtime.Registry{
        // 给定键值对，其中键为字符串类型，值为一个函数，用于构造对象
		dynamicresources.Name:                runtime.FactoryAdapter(fts, dynamicresources.New),
		selectorspread.Name:                  selectorspread.New,
		imagelocality.Name:                   imagelocality.New,
		tainttoleration.Name:                 tainttoleration.New,
		nodename.Name:                        nodename.New,
		nodeports.Name:                       nodeports.New,
		nodeaffinity.Name:                    nodeaffinity.New,
		podtopologyspread.Name:               runtime.FactoryAdapter(fts, podtopologyspread.New),
		nodeunschedulable.Name:               nodeunschedulable.New,
		noderesources.Name:                   runtime.FactoryAdapter(fts, noderesources.NewFit),
		noderesources.BalancedAllocationName: runtime.FactoryAdapter(fts, noderesources.NewBalancedAllocation),
		volumebinding.Name:                   runtime.FactoryAdapter(fts, volumebinding.New),
		volumerestrictions.Name:              runtime.FactoryAdapter(fts, volumerestrictions.New),
		volumezone.Name:                      volumezone.New,
		nodevolumelimits.CSIName:             runtime.FactoryAdapter(fts, nodevolumelimits.NewCSI),
		nodevolumelimits.EBSName:             runtime.FactoryAdapter(fts, nodevolumelimits.NewEBS),
		nodevolumelimits.GCEPDName:           runtime.FactoryAdapter(fts, nodevolumelimits.NewGCEPD),
		nodevolumelimits.AzureDiskName:       runtime.FactoryAdapter(fts, nodevolumelimits.NewAzureDisk),
		nodevolumelimits.CinderName:          runtime.FactoryAdapter(fts, nodevolumelimits.NewCinder),
		interpodaffinity.Name:                interpodaffinity.New,
		queuesort.Name:                       queuesort.New,
		defaultbinder.Name:                   defaultbinder.New,
		defaultpreemption.Name:               runtime.FactoryAdapter(fts, defaultpreemption.New),
		schedulinggates.Name:                 runtime.FactoryAdapter(fts, schedulinggates.New),
	}

	return registry
}
```

#### buildExtenders

```go
func buildExtenders(extenders []schedulerapi.Extender, profiles []schedulerapi.KubeSchedulerProfile) ([]framework.Extender, error) {
	// 定义一个名为 buildExtenders 的函数，它接受两个参数：一个名为 extenders 的类型为 []schedulerapi.Extender 的切片和一个名为 profiles 的类型为 []schedulerapi.KubeSchedulerProfile 的切片，该函数返回两个值：类型为 []framework.Extender 的切片和一个 error 类型的变量。
	var fExtenders []framework.Extender
	// 定义一个名为 fExtenders 的类型为 []framework.Extender 的空切片。
	if len(extenders) == 0 {
		return nil, nil
		// 如果 extenders 的长度为 0，则返回两个 nil 值。
	}

	var ignoredExtendedResources []string
	// 定义一个名为 ignoredExtendedResources 的类型为 []string 的空切片。
	var ignorableExtenders []framework.Extender
	// 定义一个名为 ignorableExtenders 的类型为 []framework.Extender 的空切片。
	for i := range extenders {
		// 遍历 extenders 中的每个元素。
		klog.V(2).InfoS("Creating extender", "extender", extenders[i])
		// 记录日志，输出 "Creating extender" 和 extenders[i] 的值。
		extender, err := NewHTTPExtender(&extenders[i])
		// 调用 NewHTTPExtender 函数，将 extenders[i] 的地址作为参数传递，并将其返回值分别赋值给 extender 和 err 变量。
		if err != nil {
			return nil, err
			// 如果 err 不为 nil，则返回两个 nil 值和 err。
		}
		if !extender.IsIgnorable() {
			fExtenders = append(fExtenders, extender)
			// 如果 extender 不可忽略，则将其追加到 fExtenders 中。
		} else {
			ignorableExtenders = append(ignorableExtenders, extender)
			// 否则，将其追加到 ignorableExtenders 中。
		}
		for _, r := range extenders[i].ManagedResources {
			if r.IgnoredByScheduler {
				ignoredExtendedResources = append(ignoredExtendedResources, r.Name)
				// 遍历 extenders[i].ManagedResources 中的每个元素，如果该元素的 IgnoredByScheduler 字段为 true，则将其 Name 字段的值追加到 ignoredExtendedResources 中。
			}
		}
	}
	// 将 ignorableExtenders 追加到 fExtenders 的末尾。
	fExtenders = append(fExtenders, ignorableExtenders...)

	// 如果从 Extender 中找到任何扩展资源，则将它们附加到每个 profile 的 pluginConfig 中。
	// 这只对 ComponentConfig 产生影响，在该组件中可以配置 Extender 和插件参数（在这种情况下，Extender 忽略的资源优先）。
	if len(ignoredExtendedResources) == 0 {
		return fExtenders, nil
		// 如果 ignoredExtendedResources 的长度为 0，则返回 fExtenders
	}
	// 便利每个profiles
	for i := range profiles {
		prof := &profiles[i]
		var found = false
		for k := range prof.PluginConfig {
			if prof.PluginConfig[k].Name == noderesources.Name {
                // 如果 prof.PluginConfig[k] 的 Name 属性等于 noderesources.Name，则说明这是 NodeResourcesFitArgs 插件配置，需要对其进行更新。
				// Update the existing args
				pc := &prof.PluginConfig[k]
				args, ok := pc.Args.(*schedulerapi.NodeResourcesFitArgs)
				if !ok {
					return nil, fmt.Errorf("want args to be of type NodeResourcesFitArgs, got %T", pc.Args)
				}
                // 将 ignoredExtendedResources 中的扩展资源添加到 args.IgnoredResources 中。
				args.IgnoredResources = ignoredExtendedResources
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("can't find NodeResourcesFitArgs in plugin config")
		}
	}
	return fExtenders, nil
}
```

#### Snapshot

```go
type Snapshot struct {
    // nodeInfoMap 是一个节点名称到其 NodeInfo 快照的映射。
    nodeInfoMap map[string]*framework.NodeInfo
    // nodeInfoList 是节点列表，按照缓存的 nodeTree 中的顺序排列。
    nodeInfoList []*framework.NodeInfo
    // havePodsWithAffinityNodeInfoList 是具有至少一个声明亲和性词条的 Pod 的节点列表。
    havePodsWithAffinityNodeInfoList []*framework.NodeInfo
    // havePodsWithRequiredAntiAffinityNodeInfoList 是具有至少一个声明必要反亲和性词条的 Pod 的节点列表。
    havePodsWithRequiredAntiAffinityNodeInfoList []*framework.NodeInfo
    // usedPVCSet 包含一个 PVC 名称的集合，其中至少有一个已调度的 Pod 使用了该 PVC，键格式为 "namespace/name"。
    usedPVCSet sets.Set[string]
    generation int64
}

func NewEmptySnapshot() *Snapshot {
	return &Snapshot{
		nodeInfoMap: make(map[string]*framework.NodeInfo),
		usedPVCSet:  sets.New[string](),
	}
}
```

####  profile.NewMap

```go
type Map map[string]framework.Framework

func NewMap(cfgs []config.KubeSchedulerProfile, r frameworkruntime.Registry, recorderFact RecorderFactory,
	stopCh <-chan struct{}, opts ...frameworkruntime.Option) (Map, error) {
	m := make(Map)
	v := cfgValidator{m: m}

	for _, cfg := range cfgs {
		p, err := newProfile(cfg, r, recorderFact, stopCh, opts...)
		if err != nil {
			return nil, fmt.Errorf("creating profile for scheduler name %s: %v", cfg.SchedulerName, err)
		}
		if err := v.validate(cfg, p); err != nil {
			return nil, err
		}
		m[cfg.SchedulerName] = p
	}
	return m, nil
}
```

#### Framework

```go
type Framework interface {
	Handle

	// 返回已注册的预入队插件（PreEnqueue Plugins）的列表
	PreEnqueuePlugins() []PreEnqueuePlugin

	// 返回一个用于对调度队列中的Pod进行排序的函数
	QueueSortFunc() LessFunc

	// 运行配置的预过滤器（PreFilter Plugins）集合。如果任何一个插件返回除了"Success"以外的值，则返回一个非成功（non-success）的*Status，其code字段被设置为对应的错误码。
    // 如果返回了非成功的状态，调度循环将被中止。此外，还返回一个PreFilterResult，可能会影响下游的节点评估过程。
	RunPreFilterPlugins(ctx context.Context, state *CycleState, pod *v1.Pod) (*PreFilterResult, *Status)

	// 运行配置的后过滤器（PostFilter Plugins）集合。后过滤器可以是信息性的，这种情况下应该配置为先执行并返回不可调度（Unschedulable）状态；
    // 或者是试图更改集群状态以便在将来的调度循环中使Pod可能可调度的插件。函数返回一个PostFilterResult和一个Status。
	RunPostFilterPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, filteredNodeStatusMap NodeToStatusMap) (*PostFilterResult, *Status)

	// 运行配置的预绑定插件（PreBind Plugins）。如果任何一个插件返回除了"Success"以外的值，函数返回一个非成功的*Status，其code字段被设置为对应的错误码。
    // 如果返回的Status的code为"Unschedulable"，表示调度检查失败；否则，表示内部错误。在任何情况下，Pod都不会被绑定。
	RunPreBindPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string) *Status

	// 运行配置的后绑定插件（PostBind Plugins）
	RunPostBindPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string)

	// 运行配置的预留（Reserve）插件的Reserve方法。如果任何一个调用返回错误，函数将不再继续运行剩余的插件，并返回错误。在这种情况下，Pod将不会被调度。
	RunReservePluginsReserve(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string) *Status

	// 运行配置的预留（Reserve）插件的Unreserve方法
	RunReservePluginsUnreserve(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string)

	// RunPermitPlugins 运行配置的 Permit 插件。如果任何一个插件返回除了 "Success" 或 "Wait" 外的状态，
    // 则不会继续运行剩余的插件并返回错误。否则，如果任何一个插件返回 "Wait"，
    // 则此函数将创建并添加一个等待中的 Pod 到当前等待 Pod 的映射中，并返回带有 "Wait" 状态的结果。
    // Pod 将保持为等待 Pod，直到 Permit 插件返回的最小持续时间过去。
	RunPermitPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string) *Status

	// WaitOnPermit 如果 Pod 是等待中的 Pod，则阻塞，直到等待的 Pod 被拒绝或允许。
	WaitOnPermit(ctx context.Context, pod *v1.Pod) *Status

	// RunBindPlugins 运行配置的 Bind 插件。Bind 插件可以选择是否处理给定的 Pod。
    // 如果 Bind 插件选择跳过绑定操作，则应返回 code=5（"skip"）状态。
    // 否则，应返回 "Error" 或 "Success" 状态。
    // 如果没有插件处理绑定，则 RunBindPlugins 返回 code=5（"skip"）状态。
	RunBindPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string) *Status

	// HasFilterPlugins 如果至少定义了一个 Filter 插件，则返回 true。
	HasFilterPlugins() bool

	// HasPostFilterPlugins 如果至少定义了一个 PostFilter 插件，则返回 true。
	HasPostFilterPlugins() bool

	// HasScorePlugins 如果至少定义了一个 Score 插件，则返回 true。
	HasScorePlugins() bool

	// ListPlugins 返回一个映射，其中键是扩展点的名称，值是配置的插件列表。
	ListPlugins() *config.Plugins

	// ProfileName 返回与配置文件关联的配置文件名称。
	ProfileName() string

	// PercentageOfNodesToScore 返回与配置文件关联的节点评分的百分比。
	PercentageOfNodesToScore() *int32

	// SetPodNominator 设置 PodNominator。
	SetPodNominator(nominator PodNominator)
}
```

#### applyDefaultHandlers

```go
func (s *Scheduler) applyDefaultHandlers() {
	s.SchedulePod = s.schedulePod
	s.FailureHandler = s.handleSchedulingFailure
}
```

### Run

```go
func (sched *Scheduler) Run(ctx context.Context) {
	sched.SchedulingQueue.Run()

	// 需要在单独的 goroutine 中启动 scheduleOne 循环，
    // 因为 scheduleOne 函数在从 SchedulingQueue 获取下一个项时会阻塞。
    // 如果没有新的 pod 需要调度，它将一直阻塞在这里，
    // 如果在此 goroutine 中完成，将阻塞关闭 SchedulingQueue，
    // 导致在关闭时发生死锁。
	go wait.UntilWithContext(ctx, sched.scheduleOne, 0)

	<-ctx.Done()
	sched.SchedulingQueue.Close()
}
```





