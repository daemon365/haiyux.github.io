---
title: "kube-controller-manager 代码走读"
date: 2023-03-01T21:39:58+08:00
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

## 介绍

这篇文章是关于`kube-controller-manager`的代码实现方式的介绍。它不包含每个`controller`的原理，只介绍了如何启动各个`controller`。代码位置在：`https://github.com/kubernetes/kubernetes/blob/master/cmd/kube-controller-manager`。

## 启动函数

```go
func main() {
	command := app.NewControllerManagerCommand()
	code := cli.Run(command)
	os.Exit(code)
}
```

`app.NewControllerManagerCommand()` 函数返回一个 `cmd *cobra.Command` 对象，该对象是一个命令行参数的集合。这个对象可以让你将命令绑定到其中，以便在启动时接受各种参数。例如，你可以使用该对象指定 `api-server` 证书的位置，或者指定每个控制器要启动的工作进程数量等。

`cmd *cobra.Command` 对象来源于 `spf13/cobra` 包，这个包是一个用于现代 Go CLI 交互的命令行工具。使用 `cmd *cobra.Command` 对象，你可以轻松地将命令行参数集成到你的应用程序中，以方便用户在启动时配置应用程序的各种选项。

在实际应用程序中，你可以将 `cmd *cobra.Command` 对象与其他应用程序逻辑相结合，以便在运行时自动执行一些操作，例如根据命令行参数初始化应用程序的配置等。这个功能非常有用，特别是当你需要在应用程序启动时进行一些特殊处理时。

`cli.Run(command)` 是一个自定义函数，它的作用是启动 `cmd *cobra.Command` 对象并执行其中的命令行参数。在这之前，它还可以进行一些初始化操作，例如初始化日志、设置日志级别、设置日志格式等。这些操作可以确保应用程序在启动时能够正确地记录日志，并且可以方便地进行故障排除和调试。

## NewControllerManagerCommand

```go
func NewControllerManagerCommand() *cobra.Command {
	s, err := options.NewKubeControllerManagerOptions()
	if err != nil {
		klog.Fatalf("unable to initialize command options: %v", err)
	}

	cmd := &cobra.Command{
		Use: "kube-controller-manager",
		Long: `The Kubernetes controller manager is a daemon that embeds
the core control loops shipped with Kubernetes. In applications of robotics and
automation, a control loop is a non-terminating loop that regulates the state of
the system. In Kubernetes, a controller is a control loop that watches the shared
state of the cluster through the apiserver and makes changes attempting to move the
current state towards the desired state. Examples of controllers that ship with
Kubernetes today are the replication controller, endpoints controller, namespace
controller, and serviceaccounts controller.`,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			// silence client-go warnings.
			// kube-controller-manager generically watches APIs (including deprecated ones),
			// and CI ensures it works properly against matching kube-apiserver versions.
			restclient.SetDefaultWarningHandler(restclient.NoWarnings{})
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			verflag.PrintAndExitIfRequested()

			// Activate logging as soon as possible, after that
			// show flags with the final logging configuration.
			if err := logsapi.ValidateAndApply(s.Logs, utilfeature.DefaultFeatureGate); err != nil {
				return err
			}
			cliflag.PrintFlags(cmd.Flags())

			c, err := s.Config(KnownControllers(), ControllersDisabledByDefault.List())
			if err != nil {
				return err
			}
			// add feature enablement metrics
			utilfeature.DefaultMutableFeatureGate.AddMetrics()
			return Run(c.Complete(), wait.NeverStop)
		},
		Args: func(cmd *cobra.Command, args []string) error {
			for _, arg := range args {
				if len(arg) > 0 {
					return fmt.Errorf("%q does not take any arguments, got %q", cmd.CommandPath(), args)
				}
			}
			return nil
		},
	}

	fs := cmd.Flags()
	namedFlagSets := s.Flags(KnownControllers(), ControllersDisabledByDefault.List())
	verflag.AddFlags(namedFlagSets.FlagSet("global"))
	globalflag.AddGlobalFlags(namedFlagSets.FlagSet("global"), cmd.Name(), logs.SkipLoggingConfigurationFlags())
	registerLegacyGlobalFlags(namedFlagSets)
	for _, f := range namedFlagSets.FlagSets {
		fs.AddFlagSet(f)
	}

	cols, _, _ := term.TerminalSize(cmd.OutOrStdout())
	cliflag.SetUsageAndHelpFunc(cmd, namedFlagSets, cols)

	return cmd
}
```

1. `options.NewKubeControllerManagerOptions()`： 创建一个`options` ,用来绑定命令行参数。如果出现错误，日志打印错误。
2. `cobra.Command` : 创建一个command对象 用来启动
3. `fs := cmd.Flags()`: 获取命令行参数，
4. `namedFlagSets := s.Flags(KnownControllers(), ControllersDisabledByDefault.List())`: 获取选项对象的标志集
5. `namedFlagSets := s.Flags(KnownControllers(), ControllersDisabledByDefault.List())`: 获取控制器管理器选项的命名 flag 集合，该命名 flag 集合用于特定的控制器
6. `verflag.AddFlags(namedFlagSets.FlagSet("global"))`: 向全局 flag 集合中添加命名 flag 集合的 flag
7. `globalflag.AddGlobalFlags(namedFlagSets.FlagSet("global"), cmd.Name(), logs.SkipLoggingConfigurationFlags())`: 向全局 flag 集合和命令名称、日志配置跳过标志添加全局 flag
8. `registerLegacyGlobalFlags(namedFlagSets)`: 注册传统全局 flag
9. `for _, f := range namedFlagSets.FlagSets {  fs.AddFlagSet(f) }`:  将命名 flag 集合中的 flag 集合添加到当前命令的 flag 集合中
10. `cols, _, _ := term.TerminalSize(cmd.OutOrStdout()) `: 获取终端窗口的列数
11. `cliflag.SetUsageAndHelpFunc(cmd, namedFlagSets, cols)`: 设置用法和帮助函数

​	上述代码中和把flag相关的都省略说明了不是这篇文章的重点，k8s的flag绑定使用的是`github.com/spf13/pflag`库

### options.NewKubeControllerManagerOptions()

这个函数的主要作用是创建一个名为 `options` 的对象。该对象包含了各个 `controller` 的参数以及 `kube-controller-manager` 需要的 `kubeconfig` 参数等。这些参数是通过命令行输入的方式传递进来的。

该函数首先会将这些参数绑定到一个字典对象 `options` 中，以便在后续的代码中使用。

```go
// KubeControllerManagerOptions is the main context object for the kube-controller manager.
type KubeControllerManagerOptions struct {
	Generic           *cmoptions.GenericControllerManagerConfigurationOptions
	KubeCloudShared   *cpoptions.KubeCloudSharedOptions
	ServiceController *cpoptions.ServiceControllerOptions

	AttachDetachController           *AttachDetachControllerOptions
	CSRSigningController             *CSRSigningControllerOptions
	DaemonSetController              *DaemonSetControllerOptions
	DeploymentController             *DeploymentControllerOptions
	StatefulSetController            *StatefulSetControllerOptions
	DeprecatedFlags                  *DeprecatedControllerOptions
	EndpointController               *EndpointControllerOptions
	EndpointSliceController          *EndpointSliceControllerOptions
	EndpointSliceMirroringController *EndpointSliceMirroringControllerOptions
	EphemeralVolumeController        *EphemeralVolumeControllerOptions
	GarbageCollectorController       *GarbageCollectorControllerOptions
	HPAController                    *HPAControllerOptions
	JobController                    *JobControllerOptions
	CronJobController                *CronJobControllerOptions
	NamespaceController              *NamespaceControllerOptions
	NodeIPAMController               *NodeIPAMControllerOptions
	NodeLifecycleController          *NodeLifecycleControllerOptions
	PersistentVolumeBinderController *PersistentVolumeBinderControllerOptions
	PodGCController                  *PodGCControllerOptions
	ReplicaSetController             *ReplicaSetControllerOptions
	ReplicationController            *ReplicationControllerOptions
	ResourceQuotaController          *ResourceQuotaControllerOptions
	SAController                     *SAControllerOptions
	TTLAfterFinishedController       *TTLAfterFinishedControllerOptions

	SecureServing  *apiserveroptions.SecureServingOptionsWithLoopback
	Authentication *apiserveroptions.DelegatingAuthenticationOptions
	Authorization  *apiserveroptions.DelegatingAuthorizationOptions
	Metrics        *metrics.Options
	Logs           *logs.Options

	Master                      string
	Kubeconfig                  string
	ShowHiddenMetricsForVersion string
}

// NewKubeControllerManagerOptions creates a new KubeControllerManagerOptions with a default config.
func NewKubeControllerManagerOptions() (*KubeControllerManagerOptions, error) {
	componentConfig, err := NewDefaultComponentConfig()
	if err != nil {
		return nil, err
	}

	s := KubeControllerManagerOptions{
		Generic:         cmoptions.NewGenericControllerManagerConfigurationOptions(&componentConfig.Generic),
		KubeCloudShared: cpoptions.NewKubeCloudSharedOptions(&componentConfig.KubeCloudShared),
		ServiceController: &cpoptions.ServiceControllerOptions{
			ServiceControllerConfiguration: &componentConfig.ServiceController,
		},
		AttachDetachController: &AttachDetachControllerOptions{
			&componentConfig.AttachDetachController,
		},
		CSRSigningController: &CSRSigningControllerOptions{
			&componentConfig.CSRSigningController,
		},
		DaemonSetController: &DaemonSetControllerOptions{
			&componentConfig.DaemonSetController,
		},
		DeploymentController: &DeploymentControllerOptions{
			&componentConfig.DeploymentController,
		},
		StatefulSetController: &StatefulSetControllerOptions{
			&componentConfig.StatefulSetController,
		},
		DeprecatedFlags: &DeprecatedControllerOptions{
			&componentConfig.DeprecatedController,
		},
		EndpointController: &EndpointControllerOptions{
			&componentConfig.EndpointController,
		},
		EndpointSliceController: &EndpointSliceControllerOptions{
			&componentConfig.EndpointSliceController,
		},
		EndpointSliceMirroringController: &EndpointSliceMirroringControllerOptions{
			&componentConfig.EndpointSliceMirroringController,
		},
		EphemeralVolumeController: &EphemeralVolumeControllerOptions{
			&componentConfig.EphemeralVolumeController,
		},
		GarbageCollectorController: &GarbageCollectorControllerOptions{
			&componentConfig.GarbageCollectorController,
		},
		HPAController: &HPAControllerOptions{
			&componentConfig.HPAController,
		},
		JobController: &JobControllerOptions{
			&componentConfig.JobController,
		},
		CronJobController: &CronJobControllerOptions{
			&componentConfig.CronJobController,
		},
		NamespaceController: &NamespaceControllerOptions{
			&componentConfig.NamespaceController,
		},
		NodeIPAMController: &NodeIPAMControllerOptions{
			&componentConfig.NodeIPAMController,
		},
		NodeLifecycleController: &NodeLifecycleControllerOptions{
			&componentConfig.NodeLifecycleController,
		},
		PersistentVolumeBinderController: &PersistentVolumeBinderControllerOptions{
			&componentConfig.PersistentVolumeBinderController,
		},
		PodGCController: &PodGCControllerOptions{
			&componentConfig.PodGCController,
		},
		ReplicaSetController: &ReplicaSetControllerOptions{
			&componentConfig.ReplicaSetController,
		},
		ReplicationController: &ReplicationControllerOptions{
			&componentConfig.ReplicationController,
		},
		ResourceQuotaController: &ResourceQuotaControllerOptions{
			&componentConfig.ResourceQuotaController,
		},
		SAController: &SAControllerOptions{
			&componentConfig.SAController,
		},
		TTLAfterFinishedController: &TTLAfterFinishedControllerOptions{
			&componentConfig.TTLAfterFinishedController,
		},
		SecureServing:  apiserveroptions.NewSecureServingOptions().WithLoopback(),
		Authentication: apiserveroptions.NewDelegatingAuthenticationOptions(),
		Authorization:  apiserveroptions.NewDelegatingAuthorizationOptions(),
		Metrics:        metrics.NewOptions(),
		Logs:           logs.NewOptions(),
	}

	s.Authentication.RemoteKubeConfigFileOptional = true
	s.Authorization.RemoteKubeConfigFileOptional = true

	// Set the PairName but leave certificate directory blank to generate in-memory by default
	s.SecureServing.ServerCert.CertDirectory = ""
	s.SecureServing.ServerCert.PairName = "kube-controller-manager"
	s.SecureServing.BindPort = ports.KubeControllerManagerPort

	gcIgnoredResources := make([]garbagecollectorconfig.GroupResource, 0, len(garbagecollector.DefaultIgnoredResources()))
	for r := range garbagecollector.DefaultIgnoredResources() {
		gcIgnoredResources = append(gcIgnoredResources, garbagecollectorconfig.GroupResource{Group: r.Group, Resource: r.Resource})
	}

	s.GarbageCollectorController.GCIgnoredResources = gcIgnoredResources
	s.Generic.LeaderElection.ResourceName = "kube-controller-manager"
	s.Generic.LeaderElection.ResourceNamespace = "kube-system"

	return &s, nil
}
```

### cobra.Command

`Args` 函数是检查是否有参数，有参数就报错

`PersistentPreRunE` 是在run之前执行 `restclient.SetDefaultWarningHandler(restclient.NoWarnings{})` 此处设置了 REST 客户端的默认警告处理方式为不输出任何警告信息

cobra.Command 中的 RunE

1. 调用 verflag 包的 PrintAndExitIfRequested 函数，如果输出了版本信息则直接退出程序。
2. 调用 logsapi 包的 ValidateAndApply 函数，对日志输出进行验证和应用。
3. 调用 cliflag 包的 PrintFlags 函数，将所有命令行参数的信息输出到控制台。
4. 调用 options 包的 Config 函数，获取控制器管理器的配置信息。
5. 调用RUN函数

## controllermanager中的Run



## 待更新

## Run

```go
func Run(cmd *cobra.Command) int {
	if logsInitialized, err := run(cmd); err != nil {
		if !logsInitialized {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		} else {
			klog.ErrorS(err, "command failed")
		}
		return 1
	}
	return 0
}
```

1. 调用`run`函数，它的作用是启动 `cmd` 命令并执行其中的命令行参数
2. 在执行过程中可能会出现错误，这时我们需要记录日志以便调试和故障排除。如果出现了错误，那么 `logsInitialized` 变量用于判断日志是否已经被成功初始化。如果成功，我们会使用 `klog` 来记录日志，如果没有成功，我们会使用标准错误输出来记录日志。
3. 我们会根据程序执行的状态（成功或失败）设置返回值，以便后续处理。如果发生了错误，返回值为 1，否则为 0。外面的 `os.Exit(code)` 用于设置程序的返回值。
4. 整个流程大致如下：
   - 初始化日志。
   - 执行命令行参数。
   - 如果出现错误，记录日志并返回错误信息。
   - 根据程序执行状态设置返回值。

### run

```go

func run(cmd *cobra.Command) (logsInitialized bool, err error) {
	rand.Seed(time.Now().UnixNano())
	defer logs.FlushLogs()

	cmd.SetGlobalNormalizationFunc(cliflag.WordSepNormalizeFunc)

	if !cmd.SilenceUsage {
		cmd.SilenceUsage = true
		cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {

			c.SilenceUsage = false
			return err
		})
	}

	cmd.SilenceErrors = true

	logs.AddFlags(cmd.PersistentFlags())

	switch {
	case cmd.PersistentPreRun != nil:
		pre := cmd.PersistentPreRun
		cmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
			logs.InitLogs()
			logsInitialized = true
			pre(cmd, args)
		}
	case cmd.PersistentPreRunE != nil:
		pre := cmd.PersistentPreRunE
		cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
			logs.InitLogs()
			logsInitialized = true
			return pre(cmd, args)
		}
	default:
		cmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
			logs.InitLogs()
			logsInitialized = true
		}
	}

	err = cmd.Execute()
	return
}
```

1. 定义了一个名为`run`的函数，该函数接受一个指向`cobra.Command`类型的参数`cmd`，并返回两个值，一个是`logsInitialized`的布尔值，另一个是`err`的错误值，上边用到了。

2. `defer logs.FlushLogs()` : 刷新缓存并清理日志记录器。日志记录是通过 `klog` 包实现的。日志记录器在记录日志时，有时会将日志缓存在本地，等待达到一定量后再进行批量写入。`logs.FlushLogs()` 会将这些缓存中的日志写入文件中，并清空这些日志缓存，以确保在程序退出前将所有日志写入磁盘。这可以避免由于程序异常崩溃或者日志记录出错而导致丢失部分日志记录。

3. `cmd.SetGlobalNormalizationFunc(cliflag.WordSepNormalizeFunc)`：`cmd.SetGlobalNormalizationFunc`为cobra功能，作用是对标志参数名称进行规范化，以保证在处理参数时，不会因为名称大小写等原因导致出现错误。这里就是把所有的`_`替换成"-"。

   ```go
   // WordSepNormalizeFunc changes all flags that contain "_" separators
   func WordSepNormalizeFunc(f *pflag.FlagSet, name string) pflag.NormalizedName {
   	if strings.Contains(name, "_") {
   		return pflag.NormalizedName(strings.Replace(name, "_", "-", -1))
   	}
   	return pflag.NormalizedName(name)
   }
   ```

4. `SilenceUsage` 和 `SilenceErrors` 分别为反生错误时时候输出用法信息和错误信息。这里设置为`true`是避免删除无用信息对错误本身的信息进行干扰。错误信息由自己日志输出。

   ```go
   if !cmd.SilenceUsage {
   		cmd.SilenceUsage = true
   		cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
   			// Re-enable usage printing.
   			c.SilenceUsage = false
   			return err
   		})
   	}
   
   	// In all cases error printing is done below.
   	cmd.SilenceErrors = true
   ```

5. `	logs.AddFlags(cmd.PersistentFlags())`：向指定的 `pflag.FlagSet` 添加日志输出相关的标志。通过添加这些标志，可以方便地控制日志输出的级别、格式、输出位置等行为。

6. 这段代码是针对 `cmd` 命令设置 `PersistentPreRun` 钩子函数的，该函数会在执行子命令之前被调用。这段代码的作用是在执行子命令之前，先初始化日志，以确保后续的日志输出操作能够正常工作

   - 判断 `cmd` 是否设置了 `PersistentPreRun` 钩子函数，如果设置了，则先将该钩子函数保存起来，然后重新设置 `cmd` 的 `PersistentPreRun` 钩子函数，将原有的钩子函数包装在新的钩子函数内部，并在包装函数中加入了一个初始化日志的操作。
   - 如果 `cmd` 设置了 `PersistentPreRunE` 钩子函数，也会执行相似的操作，但是包装函数需要返回一个错误类型。
   - 如果 `cmd` 没有设置 `PersistentPreRun` 和 `PersistentPreRunE` 钩子函数，则设置一个默认的钩子函数，也是将原有的钩子函数包装在新的钩子函数内部，并在包装函数中加入了一个初始化日志的操作。

   ```go
   switch {
   	case cmd.PersistentPreRun != nil:
   		pre := cmd.PersistentPreRun
   		cmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
   			logs.InitLogs()
   			logsInitialized = true
   			pre(cmd, args)
   		}
   	case cmd.PersistentPreRunE != nil:
   		pre := cmd.PersistentPreRunE
   		cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
   			logs.InitLogs()
   			logsInitialized = true
   			return pre(cmd, args)
   		}
   	default:
   		cmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
   			logs.InitLogs()
   			logsInitialized = true
   		}
   	}
   ```

7. `err = cmd.Execute()` ：执行`cmd`

## Reference

- [kubernetes/cmd/kube-controller-manager at master · kubernetes/kubernetes (github.com)](https://github.com/kubernetes/kubernetes/tree/master/cmd/kube-controller-manager)
- [spf13/cobra: A Commander for modern Go CLI interactions (github.com)](https://github.com/spf13/cobra)
- [spf13/pflag: Drop-in replacement for Go's flag package, implementing POSIX/GNU-style --flags. (github.com)](https://github.com/spf13/pflag)
