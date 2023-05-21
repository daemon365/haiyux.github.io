---
title: "kube-apiserver prerun和run 代码走读"
subtitle:
date: 2023-05-21T17:26:09+08:00
draft: false
toc: true
categories: [cloud]
tags: [kubernetes]
authors:
    - haiyux
featuredImagePreview: /img/k8s.webp
---

## PrepareRun

```GO
// PrepareRun 准备聚合器运行，设置 OpenAPI 规范和聚合发现文档，并调用通用的 PrepareRun 方法。
func (s *APIAggregator) PrepareRun() (preparedAPIAggregator, error) {
	// 在通用的 PrepareRun 之前添加后启动钩子，以便在 /healthz 安装之前执行
	if s.openAPIConfig != nil {
		s.GenericAPIServer.AddPostStartHookOrDie("apiservice-openapi-controller", func(context genericapiserver.PostStartHookContext) error {
			go s.openAPIAggregationController.Run(context.StopCh)
			return nil
		})
	}

	if s.openAPIV3Config != nil && utilfeature.DefaultFeatureGate.Enabled(genericfeatures.OpenAPIV3) {
		s.GenericAPIServer.AddPostStartHookOrDie("apiservice-openapiv3-controller", func(context genericapiserver.PostStartHookContext) error {
			go s.openAPIV3AggregationController.Run(context.StopCh)
			return nil
		})
	}

	if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.AggregatedDiscoveryEndpoint) {
		s.discoveryAggregationController = NewDiscoveryManager(
			// 使用聚合器作为源名称，以避免覆盖本地/CRD 组
			s.GenericAPIServer.AggregatedDiscoveryGroupManager.WithSource(aggregated.AggregatorSource),
		)

		// 设置发现端点
		s.GenericAPIServer.AddPostStartHookOrDie("apiservice-discovery-controller", func(context genericapiserver.PostStartHookContext) error {
			// 运行发现管理器的 worker，以监视新建/删除/更新的 APIServices，以便在运行时更新发现文档
			go s.discoveryAggregationController.Run(context.StopCh)
			return nil
		})
	}

	prepared := s.GenericAPIServer.PrepareRun()

	// 延迟设置 OpenAPI，直到委托对象有机会设置其 OpenAPI 处理程序
	if s.openAPIConfig != nil {
		specDownloader := openapiaggregator.NewDownloader()
		openAPIAggregator, err := openapiaggregator.BuildAndRegisterAggregator(
			&specDownloader,
			s.GenericAPIServer.NextDelegate(),
			s.GenericAPIServer.Handler.GoRestfulContainer.RegisteredWebServices(),
			s.openAPIConfig,
			s.GenericAPIServer.Handler.NonGoRestfulMux)
		if err != nil {
			return preparedAPIAggregator{}, err
		}
		s.openAPIAggregationController = openapicontroller.NewAggregationController(&specDownloader, openAPIAggregator)
	}

	if s.openAPIV3Config != nil && utilfeature.DefaultFeatureGate.Enabled(genericfeatures.OpenAPIV3) {
		specDownloaderV3 := openapiv3aggregator.NewDownloader()
		openAPIV3Aggregator, err := openapiv3aggregator.BuildAndRegisterAggregator(
			specDownloaderV3,
			s.GenericAPIServer.NextDelegate(),
			s.GenericAPIServer.Handler.NonGoRestfulMux)
		if err != nil {
			return preparedAPIAggregator{}, err
		}
		s.openAPIV3AggregationController = openapiv3controller.NewAggregationController(openAPIV3Aggregator)
	}

	return preparedAPIAggregator{APIAggregator: s, runnable: prepared}, nil
}
```

### PrepareRun

```GO
// PrepareRun 执行 API 安装后的设置步骤。它递归调用代理的相同函数。
func (s *GenericAPIServer) PrepareRun() preparedGenericAPIServer {
	s.delegationTarget.PrepareRun()

	// 如果开启了 OpenAPI 并且未跳过 OpenAPI 安装，则安装 OpenAPI v2。
	if s.openAPIConfig != nil && !s.skipOpenAPIInstallation {
		s.OpenAPIVersionedService, s.StaticOpenAPISpec = routes.OpenAPI{
			Config: s.openAPIConfig,
		}.InstallV2(s.Handler.GoRestfulContainer, s.Handler.NonGoRestfulMux)
	}

	// 如果开启了 OpenAPI v3 并且未跳过 OpenAPI 安装，则安装 OpenAPI v3。
	if s.openAPIV3Config != nil && !s.skipOpenAPIInstallation {
		if utilfeature.DefaultFeatureGate.Enabled(features.OpenAPIV3) {
			s.OpenAPIV3VersionedService = routes.OpenAPI{
				Config: s.openAPIV3Config,
			}.InstallV3(s.Handler.GoRestfulContainer, s.Handler.NonGoRestfulMux)
		}
	}

	// 安装 /healthz 和 /livez 路由。
	s.installHealthz()
	s.installLivez()

	// 一旦启动了关闭过程，readiness 将开始失败。
	readinessStopCh := s.lifecycleSignals.ShutdownInitiated.Signaled()
	err := s.addReadyzShutdownCheck(readinessStopCh)
	if err != nil {
		klog.Errorf("Failed to install readyz shutdown check %s", err)
	}
	s.installReadyz()

	return preparedGenericAPIServer{s}
}

// preparedGenericAPIServer 是一个私有的包装器，它强制在调用 Run 之前先调用 PrepareRun。
type preparedGenericAPIServer struct {
	*GenericAPIServer
}
```

## Run

```GO
// preparedAPIAggregator 是一个私有的包装器，它强制在调用 Run 之前先调用 PrepareRun。
type preparedAPIAggregator struct {
	*APIAggregator
	runnable runnable
}

// Run 运行 APIAggregator。
func (s preparedAPIAggregator) Run(stopCh <-chan struct{}) error {
	return s.runnable.Run(stopCh)
}
```

```GO
// Run函数用于启动安全的HTTP服务器。只有当stopCh被关闭或安全端口无法初始监听时，该函数才会返回。
// 下面是依赖关系的示意图，显示了各个通道/信号之间的依赖关系：
//
// |                                  stopCh
// |                                    |
// |           ---------------------------------------------------------
// |           |                                                       |
// |    ShutdownInitiated (shutdownInitiatedCh)                        |
// |           |                                                       |
// | (ShutdownDelayDuration)                                    (PreShutdownHooks)
// |           |                                                       |
// |  AfterShutdownDelayDuration (delayedStopCh)   PreShutdownHooksStopped (preShutdownHooksHasStoppedCh)
// |           |                                                       |
// |           |-------------------------------------------------------|
// |                                    |
// |                                    |
// |               NotAcceptingNewRequest (notAcceptingNewRequestCh)
// |                                    |
// |                                    |
// |           |----------------------------------------------------------------------------------|
// |           |                        |              |                                          |
// |        [without                 [with             |                                          |
// | ShutdownSendRetryAfter]  ShutdownSendRetryAfter]  |                                          |
// |           |                        |              |                                          |
// |           |                        ---------------|                                          |
// |           |                                       |                                          |
// |           |                      |----------------|-----------------------|                  |
// |           |                      |                                        |                  |
// |           |         (NonLongRunningRequestWaitGroup::Wait)   (WatchRequestWaitGroup::Wait)   |
// |           |                      |                                        |                  |
// |           |                      |------------------|---------------------|                  |
// |           |                                         |                                        |
// |           |                         InFlightRequestsDrained (drainedCh)                      |
// |           |                                         |                                        |
// |           |-------------------|---------------------|----------------------------------------|
// |                               |                     |
// |                       stopHttpServerCh     (AuditBackend::Shutdown())
// |                               |
// |                       listenerStoppedCh
// |                               |
// |      HTTPServerStoppedListening (httpServerStoppedListeningCh)
func (s preparedGenericAPIServer) Run(stopCh <-chan struct{}) error {
	delayedStopCh := s.lifecycleSignals.AfterShutdownDelayDuration
	shutdownInitiatedCh := s.lifecycleSignals.ShutdownInitiated

	// 在关闭时清理资源。
	defer s.Destroy()

	// 如果启用了 UDS profiling，则启动一个监听在该 socket 上的本地 HTTP 服务器
	if s.UnprotectedDebugSocket != nil {
		go func() {
			defer utilruntime.HandleCrash()
			klog.Error(s.UnprotectedDebugSocket.Run(stopCh))
		}()
	}

	// 为关闭 MuxAndDiscoveryComplete 信号而产生一个新的 goroutine
	// 注册是在构建通用 API 服务器期间进行的
	// 链中的最后一个服务器会聚合前面实例的信号
	go func() {
		for _, muxAndDiscoveryCompletedSignal := range s.GenericAPIServer.MuxAndDiscoveryCompleteSignals() {
			select {
			case <-muxAndDiscoveryCompletedSignal:
				continue
			case <-stopCh:
				klog.V(1).Infof("haven't completed %s, stop requested", s.lifecycleSignals.MuxAndDiscoveryComplete.Name())
				return
			}
		}
		s.lifecycleSignals.MuxAndDiscoveryComplete.Signal()
		klog.V(1).Infof("%s has all endpoints registered and discovery information is complete", s.lifecycleSignals.MuxAndDiscoveryComplete.Name())
	}()

	go func() {
		defer delayedStopCh.Signal()
		defer klog.V(1).InfoS("[graceful-termination] shutdown event", "name", delayedStopCh.Name())

		<-stopCh

		// 一旦启动关闭过程，/readyz 应该开始返回失败。
		// 这给负载均衡器一个时间窗口（由 ShutdownDelayDuration 定义）来检测到 /readyz 是红色的
		// 并停止将流量发送到该服务器。
		shutdownInitiatedCh.Signal()
		klog.V(1).InfoS("[graceful-termination] shutdown event", "name", shutdownInitiatedCh.Name())

		time.Sleep(s.ShutdownDelayDuration)
	}()

	// 在延迟的 stopCh 后关闭 socket
	shutdownTimeout := s.ShutdownTimeout
	if s.ShutdownSendRetryAfter {
		// 当启用此模式时，我们会执行以下操作：
		// - 服务器将继续监听，直到所有已发出的请求已完成
		//   （不包括活动的长时间运行的请求）。
		// - 一旦完成，将使用 2 秒的超时调用 http.Server.Shutdown，
		//   net/http 会等待 1 秒钟，以便对等方响应 GO_AWAY 帧，
		//   因此我们应该等待至少 2 秒。
		shutdownTimeout = 2 * time.Second
		klog.V(1).InfoS("[graceful-termination] using HTTP Server shutdown timeout", "shutdownTimeout", shutdownTimeout)
	}

	notAcceptingNewRequestCh := s.lifecycleSignals.NotAcceptingNewRequest
	drainedCh := s.lifecycleSignals.InFlightRequestsDrained
	stopHttpServerCh := make(chan struct{})
	go func() {
		defer close(stopHttpServerCh)

		timeToStopHttpServerCh := notAcceptingNewRequestCh.Signaled()
		if s.ShutdownSendRetryAfter {
			timeToStopHttpServerCh = drainedCh.Signaled()
		}

		<-timeToStopHttpServerCh
	}()

	// 在任何请求到达之前启动审计后端。这意味着我们必须在 http 服务器开始服务之前调用 Backend.Run。
	// 否则，Backend.ProcessEvents 调用可能会阻塞。
	// AuditBackend.Run 将会在所有正在处理的请求被处理完毕后停止。
	if s.AuditBackend != nil {
		if err := s.AuditBackend.Run(drainedCh.Signaled()); err != nil {
			return fmt.Errorf("failed to run the audit backend: %v", err)
		}
	}

	stoppedCh, listenerStoppedCh, err := s.NonBlockingRun(stopHttpServerCh, shutdownTimeout)
	if err != nil {
		return err
	}

	httpServerStoppedListeningCh := s.lifecycleSignals.HTTPServerStoppedListening
	go func() {
		<-listenerStoppedCh
		httpServerStoppedListeningCh.Signal()
		klog.V(1).InfoS("[graceful-termination] shutdown event", "name", httpServerStoppedListeningCh.Name())
	}()

	// 只有在两个 ShutdownDelayDuration 和 preShutdown 钩子完成之后，我们才不接受新请求。
	preShutdownHooksHasStoppedCh := s.lifecycleSignals.PreShutdownHooksStopped
	go func() {
		defer klog.V(1).InfoS("[graceful-termination] shutdown event", "name", notAcceptingNewRequestCh.Name())
		defer notAcceptingNewRequestCh.Signal()

		// 等待延迟的 stopCh 后再关闭处理程序链
		<-delayedStopCh.Signaled()

		// 此外，还需要等待 preShutdown 钩子也完成，因为其中一些钩子需要向其发送 API 调用以清理自己
		// （例如，租约协调器从活动服务器中删除自身）。
		<-preShutdownHooksHasStoppedCh.Signaled()
	}()

	// 等待所有非长时间运行的请求完成
	nonLongRunningRequestDrainedCh := make(chan struct{})
	go func() {
		defer close(nonLongRunningRequestDrainedCh)
		defer klog.V(1).Info("[graceful-termination] in-flight non long-running request(s) have drained")

		// 等待延迟的 stopCh 后再关闭处理程序链（在 Wait 被调用后，它拒绝接受任何内容）。
		<-notAcceptingNewRequestCh.Signaled()

		// 等待所有请求完成，这些请求受到 RequestTimeout 变量的限制。
		// 一旦调用了 NonLongRunningRequestWaitGroup.Wait，预期 apiserver 会
		// 使用 {503, Retry-After} 响应拒绝任何传入请求，通过 WithWaitGroup 过滤器。
		// 相反，我们观察到传入的请求会得到 'connection refused' 错误，这是因为在这一点上，
		// 我们已经调用了 'Server.Shutdown'，而 net/http 服务器已经停止监听。
		// 这导致传入的请求得到 'connection refused' 错误。
		// 另一方面，如果启用了 'ShutdownSendRetryAfter'，传入的请求将以 {429, Retry-After}
		// 的形式被拒绝，因为只有在处理完正在处理的请求后，'Server.Shutdown' 才会被调用。
		// TODO: 我们能否合并这两种优雅终止的模式？
		s.NonLongRunningRequestWaitGroup.Wait()
	}()

	// 等待所有正在处理的 watch 请求完成
	activeWatchesDrainedCh := make(chan struct{})
	go func() {
		defer close(activeWatchesDrainedCh)

		<-notAcceptingNewRequestCh.Signaled()
		if s.ShutdownWatchTerminationGracePeriod <= time.Duration(0) {
			klog.V(1).InfoS("[graceful-termination] not going to wait for active watch request(s) to drain")
			return
		}

		// 等待所有活动的 watch 请求完成
		grace := s.ShutdownWatchTerminationGracePeriod
		activeBefore, activeAfter, err := s.WatchRequestWaitGroup.Wait(func(count int) (utilwaitgroup.RateLimiter, context.Context, context.CancelFunc) {
			qps := float64(count) / grace.Seconds()
			// TODO: 我们不希望 QPS（每秒最大处理请求数）低于某个最低值，
			// 因为我们希望服务器尽快处理活动的 watch 请求。
			// 目前，它是硬编码为 200，并且可能会根据规模测试的结果进行更改。
			if qps < 200 {
				qps = 200
			}

			ctx, cancel := context.WithTimeout(context.Background(), grace)
			// 我们不希望在单个 Wait 调用中消耗超过一个令牌，
			// 因此将 burst 设置为 1。
			return rate.NewLimiter(rate.Limit(qps), 1), ctx, cancel
		})
		klog.V(1).InfoS("[graceful-termination] active watch request(s) have drained",
			"duration", grace, "activeWatchesBefore", activeBefore, "activeWatchesAfter", activeAfter, "error", err)
	}()

	go func() {
		defer klog.V(1).InfoS("[graceful-termination] shutdown event", "name", drainedCh.Name())
		defer drainedCh.Signal()

		<-nonLongRunningRequestDrainedCh
		<-activeWatchesDrainedCh
	}()

	klog.V(1).Info("[graceful-termination] waiting for shutdown to be initiated")
	<-stopCh

	// 直接运行关闭钩子。这包括在 kube-apiserver 的情况下从 Kubernetes 端点注销。
	func() {
		defer func() {
			preShutdownHooksHasStoppedCh.Signal()
			klog.V(1).InfoS("[graceful-termination] pre-shutdown hooks completed", "name", preShutdownHooksHasStoppedCh.Name())
		}()
		err = s.RunPreShutdownHooks()
	}()
	if err != nil {
		return err
	}

	// Wait for all requests in flight to drain, bounded by the RequestTimeout variable.
	<-drainedCh.Signaled()

	if s.AuditBackend != nil {
		s.AuditBackend.Shutdown()
		klog.V(1).InfoS("[graceful-termination] audit backend shutdown completed")
	}

	// wait for stoppedCh that is closed when the graceful termination (server.Shutdown) is finished.
	<-listenerStoppedCh
	<-stoppedCh

	klog.V(1).Info("[graceful-termination] apiserver is exiting")
	return nil
}
```

### RunPreShutdownHooks

```GO
// RunPreShutdownHooks 运行服务器的 PreShutdownHooks
func (s *GenericAPIServer) RunPreShutdownHooks() error {
	var errorList []error

	s.preShutdownHookLock.Lock() // 锁定 preShutdownHookLock
	defer s.preShutdownHookLock.Unlock() // 函数结束后解锁 preShutdownHookLock
	s.preShutdownHooksCalled = true // 设置 preShutdownHooksCalled 为 true

	for hookName, hookEntry := range s.preShutdownHooks { // 遍历 preShutdownHooks
		if err := runPreShutdownHook(hookName, hookEntry); err != nil { // 运行 PreShutdownHook
			errorList = append(errorList, err) // 将错误添加到 errorList 中
		}
	}
	return utilerrors.NewAggregate(errorList) // 返回聚合后的错误
}
```

### NonBlockingRun

```GO
// NonBlockingRun 启动安全的 HTTP 服务器。如果无法监听安全端口，则返回错误。
// 返回的通道在（异步）终止完成时关闭。
func (s preparedGenericAPIServer) NonBlockingRun(stopCh <-chan struct{}, shutdownTimeout time.Duration) (<-chan struct{}, <-chan struct{}, error) {
	// 使用内部的停止通道允许在出错时清理监听器。
	internalStopCh := make(chan struct{})
	var stoppedCh <-chan struct{}
	var listenerStoppedCh <-chan struct{}
	if s.SecureServingInfo != nil && s.Handler != nil { // 检查是否有安全服务信息和处理程序
		var err error
		stoppedCh, listenerStoppedCh, err = s.SecureServingInfo.Serve(s.Handler, shutdownTimeout, internalStopCh) // 启动安全服务
		if err != nil {
			close(internalStopCh)
			return nil, nil, err
		}
	}

	// 现在监听器已成功绑定，由调用者负责关闭提供的通道以确保清理。
	go func() {
		<-stopCh
		close(internalStopCh)
	}()

	s.RunPostStartHooks(stopCh) // 运行后启动钩子

	if _, err := systemd.SdNotify(true, "READY=1\n"); err != nil { // 向 systemd 发送成功启动的消息
		klog.Errorf("Unable to send systemd daemon successful start message: %v\n", err)
	}

	return stoppedCh, listenerStoppedCh, nil // 返回通道
}
```

#### Serve

```GO
// Serve 运行安全的 HTTP 服务器。仅在无法加载证书或初始监听调用失败时失败。
// 实际的服务器循环（通过关闭 stopCh 可停止）在一个 Go 协程中运行，即 Serve 不会阻塞。
// 它返回一个 stoppedCh，在所有非劫持的活动请求处理完毕后关闭。
// 它返回一个 listenerStoppedCh，在底层的 http Server 停止监听时关闭。
func (s *SecureServingInfo) Serve(handler http.Handler, shutdownTimeout time.Duration, stopCh <-chan struct{}) (<-chan struct{}, <-chan struct{}, error) {
	if s.Listener == nil { // 检查 Listener 是否为 nil
		return nil, nil, fmt.Errorf("listener must not be nil")
	}

	tlsConfig, err := s.tlsConfig(stopCh) // 获取 TLS 配置
	if err != nil {
		return nil, nil, err
	}

	secureServer := &http.Server{
		Addr:           s.Listener.Addr().String(), // 使用 Listener 的地址
		Handler:        handler, // 设置处理程序
		MaxHeaderBytes: 1 << 20, // 最大请求头大小，默认 1MB
		TLSConfig:      tlsConfig, // 设置 TLS 配置

		IdleTimeout:       90 * time.Second, // 与 http.DefaultTransport 的 keep-alive 超时时间匹配
		ReadHeaderTimeout: 32 * time.Second, // 略小于 requestTimeoutUpperBound
	}

	// 至少有 99% 的序列化资源在调查的集群中小于 256KB。
	// 这个大小应该足够容纳大多数 API 的 POST 请求，并且足够小以允许每个连接的缓冲区大小乘以 `MaxConcurrentStreams`。
	const resourceBody99Percentile = 256 * 1024

	http2Options := &http2.Server{
		IdleTimeout: 90 * time.Second, // 与 http.DefaultTransport 的 keep-alive 超时时间匹配
	}

	// 将每个流的缓冲区大小和最大帧大小从 1MB 默认值缩小，同时仍然适应大多数 API 的 POST 请求的单个帧
	http2Options.MaxUploadBufferPerStream = resourceBody99Percentile
	http2Options.MaxReadFrameSize = resourceBody99Percentile

	// 使用覆盖的并发流设置或将默认值 250 显式指定，以便我们可以适当地调整 MaxUploadBufferPerConnection 的大小
	if s.HTTP2MaxStreamsPerConnection > 0 {
		http2Options.MaxConcurrentStreams = uint32(s.HTTP2MaxStreamsPerConnection)
	} else {
		http2Options.MaxConcurrentStreams = 250
	}

	// 将连接缓冲区大小从 1MB 默认值增加到处理指定数量并发流的大小
	http2Options.MaxUploadBufferPerConnection = http2Options.MaxUploadBufferPerStream * int32(http2Options.MaxConcurrentStreams)

	if !s.DisableHTTP2 { // 检查是否禁用了 HTTP/2
		// 应用设置到服务器
		if err := http2.ConfigureServer(secureServer, http2Options); err != nil {
			return nil, nil, fmt.Errorf("error configuring http2: %v", err)
		}
	}

	// 使用 tlsHandshakeErrorWriter 处理 TLS 握手错误消息
	tlsErrorWriter := &tlsHandshakeErrorWriter{os.Stderr}
	tlsErrorLogger := log.New(tlsErrorWriter, "", 0)
	secureServer.ErrorLog = tlsErrorLogger

	klog.Infof("Serving securely on %s", secureServer.Addr) // 打印服务器地址
	return RunServer(secureServer, s.Listener, shutdownTimeout, stopCh) // 运行服务器并返回通道
}

```

##### RunServer

```GO
// RunServer 在 stopCh 关闭之前，生成一个 Go 协程不断提供服务。
// 它返回一个 stoppedCh，在所有非劫持的活动请求处理完毕后关闭。
// 此函数不会阻塞。
// TODO: 当 kube-apiserver 中的非安全服务消失时，将其设为私有
func RunServer(
	server *http.Server,
	ln net.Listener,
	shutDownTimeout time.Duration,
	stopCh <-chan struct{},
) (<-chan struct{}, <-chan struct{}, error) {
	if ln == nil { // 检查 Listener 是否为 nil
		return nil, nil, fmt.Errorf("listener must not be nil")
	}

	// 优雅地关闭服务器
	serverShutdownCh, listenerStoppedCh := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(serverShutdownCh)
		<-stopCh
		ctx, cancel := context.WithTimeout(context.Background(), shutDownTimeout)
		server.Shutdown(ctx)
		cancel()
	}()

	go func() {
		defer utilruntime.HandleCrash()
		defer close(listenerStoppedCh)

		var listener net.Listener
		listener = tcpKeepAliveListener{ln}
		if server.TLSConfig != nil {
			listener = tls.NewListener(listener, server.TLSConfig)
		}

		err := server.Serve(listener)

		msg := fmt.Sprintf("Stopped listening on %s", ln.Addr().String())
		select {
		case <-stopCh:
			klog.Info(msg)
		default:
			panic(fmt.Sprintf("%s due to error: %v", msg, err))
		}
	}()

	return serverShutdownCh, listenerStoppedCh, nil // 返回相应的通道
}
```

#### RunPostStartHooks

```GO
// RunPostStartHooks 运行服务器的 PostStartHooks
func (s *GenericAPIServer) RunPostStartHooks(stopCh <-chan struct{}) {
	s.postStartHookLock.Lock() // 锁定 postStartHookLock
	defer s.postStartHookLock.Unlock() // 函数结束后解锁 postStartHookLock
	s.postStartHooksCalled = true // 设置 postStartHooksCalled 为 true

	context := PostStartHookContext{
		LoopbackClientConfig: s.LoopbackClientConfig, // 设置 LoopbackClientConfig
		StopCh:               stopCh, // 设置 StopCh
	}

	for hookName, hookEntry := range s.postStartHooks { // 遍历 postStartHooks
		go runPostStartHook(hookName, hookEntry, context) // 并发运行 PostStartHook
	}
}
```

## Hook
