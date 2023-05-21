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

## Controller

### APIExtensionsServer

#### EstablishingController

控制自 CRD 的建立过程

```go
// EstablishingController控制CRD的建立方式和时间。
type EstablishingController struct {
	crdClient client.CustomResourceDefinitionsGetter // CRD客户端
	crdLister listers.CustomResourceDefinitionLister // CRD列表
	crdSynced cache.InformerSynced // CRD Informer是否已同步

	// 用于测试的注入功能。
	syncFn func(key string) error // 同步函数

	queue workqueue.RateLimitingInterface // 工作队列
}

// NewEstablishingController创建一个新的EstablishingController。
func NewEstablishingController(crdInformer informers.CustomResourceDefinitionInformer,
	crdClient client.CustomResourceDefinitionsGetter) *EstablishingController {
	ec := &EstablishingController{
		crdClient: crdClient,
		crdLister: crdInformer.Lister(),
		crdSynced: crdInformer.Informer().HasSynced,
		queue:     workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "crdEstablishing"), // 创建具有默认速率限制的工作队列
	}

	ec.syncFn = ec.sync // 将sync函数赋值给syncFn

	return ec
}

// QueueCRD将CRD添加到建立队列中。
func (ec *EstablishingController) QueueCRD(key string, timeout time.Duration) {
	ec.queue.AddAfter(key, timeout) // 将key添加到队列中，等待指定的超时时间后执行
}

// Run启动EstablishingController。
func (ec *EstablishingController) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash() // 发生崩溃时进行处理
	defer ec.queue.ShutDown() // 关闭工作队列

	klog.Info("Starting EstablishingController") // 打印日志：开始启动EstablishingController
	defer klog.Info("Shutting down EstablishingController") // 打印日志：关闭EstablishingController

	if !cache.WaitForCacheSync(stopCh, ec.crdSynced) { // 等待缓存同步
		return
	}

	// 只启动一个工作线程，因为API响应较慢
	go wait.Until(ec.runWorker, time.Second, stopCh)

	<-stopCh // 等待停止信号
}

func (ec *EstablishingController) runWorker() {
	for ec.processNextWorkItem() {
	}
}

// processNextWorkItem处理队列中的一个键。
// 当需要退出时返回false。
func (ec *EstablishingController) processNextWorkItem() bool {
	key, quit := ec.queue.Get()
	if quit {
		return false
	}
	defer ec.queue.Done(key)

	err := ec.syncFn(key.(string))
	if err == nil {
		ec.queue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with: %v", key, err))
	ec.queue.AddRateLimited(key)

	return true
}

// sync用于将CRD转换为已建立状态。
func (ec *EstablishingController) sync(key string) error {
	cachedCRD, err := ec.crdLister.Get(key) // 从缓存中获取指定key的CRD
	if apierrors.IsNotFound(err) {
		return nil // 如果CRD不存在，则返回nil
	}
	if err != nil {
		return err // 如果发生错误，则返回错误
	}

	// 如果CRD的NamesAccepted条件不为true，或者Established条件为true，则返回nil
	if !apiextensionshelpers.IsCRDConditionTrue(cachedCRD, apiextensionsv1.NamesAccepted) ||
		apiextensionshelpers.IsCRDConditionTrue(cachedCRD, apiextensionsv1.Established) {
		return nil
	}

	crd := cachedCRD.DeepCopy() // 创建CRD的副本
	establishedCondition := apiextensionsv1.CustomResourceDefinitionCondition{
		Type:    apiextensionsv1.Established,
		Status:  apiextensionsv1.ConditionTrue,
		Reason:  "InitialNamesAccepted",
		Message: "the initial names have been accepted",
	}
	apiextensionshelpers.SetCRDCondition(crd, establishedCondition) // 设置CRD的Established条件为true

	// 使用新的CRD条件更新服务器。
	_, err = ec.crdClient.CustomResourceDefinitions().UpdateStatus(context.TODO(), crd, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		// 如果在此期间已删除或更改，则会再次调用
		return nil
	}
	if err != nil {
		return err
	}

	return nil
}
```

#### DiscoveryController

确保Kubernetes API Server能够提供完整的API发现信息，包括API组、版本和资源。

```GO
type DiscoveryController struct {
	versionHandler  *versionDiscoveryHandler // 版本处理器
	groupHandler    *groupDiscoveryHandler // 分组处理器
	resourceManager discoveryendpoint.ResourceManager // 资源管理器

	crdLister  listers.CustomResourceDefinitionLister // 自定义资源定义列表器
	crdsSynced cache.InformerSynced // 自定义资源定义是否同步

	// To allow injection for testing.
	syncFn func(version schema.GroupVersion) error // 同步函数

	queue workqueue.RateLimitingInterface // 工作队列
}

func NewDiscoveryController(
	crdInformer informers.CustomResourceDefinitionInformer, // 自定义资源定义Informer
	versionHandler *versionDiscoveryHandler, // 版本处理器
	groupHandler *groupDiscoveryHandler, // 分组处理器
	resourceManager discoveryendpoint.ResourceManager, // 资源管理器
) *DiscoveryController {
	c := &DiscoveryController{
		versionHandler:  versionHandler,
		groupHandler:    groupHandler,
		resourceManager: resourceManager,
		crdLister:       crdInformer.Lister(),
		crdsSynced:      crdInformer.Informer().HasSynced,

		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "DiscoveryController"), // 创建工作队列
	}

	// 为自定义资源定义Informer添加事件处理函数
	crdInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addCustomResourceDefinition,
		UpdateFunc: c.updateCustomResourceDefinition,
		DeleteFunc: c.deleteCustomResourceDefinition,
	})

	c.syncFn = c.sync // 设置同步函数

	return c
}

func (c *DiscoveryController) enqueue(obj *apiextensionsv1.CustomResourceDefinition) {
	for _, v := range obj.Spec.Versions {
		c.queue.Add(schema.GroupVersion{Group: obj.Spec.Group, Version: v.Name})
	}
}


func (c *DiscoveryController) addCustomResourceDefinition(obj interface{}) {
	castObj := obj.(*apiextensionsv1.CustomResourceDefinition)
	klog.V(4).Infof("Adding customresourcedefinition %s", castObj.Name)
	c.enqueue(castObj)
}

func (c *DiscoveryController) updateCustomResourceDefinition(oldObj, newObj interface{}) {
	castNewObj := newObj.(*apiextensionsv1.CustomResourceDefinition)
	castOldObj := oldObj.(*apiextensionsv1.CustomResourceDefinition)
	klog.V(4).Infof("Updating customresourcedefinition %s", castOldObj.Name)
	// Enqueue both old and new object to make sure we remove and add appropriate Versions.
	// The working queue will resolve any duplicates and only changes will stay in the queue.
	c.enqueue(castNewObj)
	c.enqueue(castOldObj)
}

func (c *DiscoveryController) deleteCustomResourceDefinition(obj interface{}) {
	castObj, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Couldn't get object from tombstone %#v", obj)
			return
		}
		castObj, ok = tombstone.Obj.(*apiextensionsv1.CustomResourceDefinition)
		if !ok {
			klog.Errorf("Tombstone contained object that is not expected %#v", obj)
			return
		}
	}
	klog.V(4).Infof("Deleting customresourcedefinition %q", castObj.Name)
	c.enqueue(castObj)
}

func (c *DiscoveryController) Run(stopCh <-chan struct{}, synchedCh chan<- struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()
	defer klog.Info("Shutting down DiscoveryController")

	klog.Info("Starting DiscoveryController")

	if !cache.WaitForCacheSync(stopCh, c.crdsSynced) {
		utilruntime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}

	// initially sync all group versions to make sure we serve complete discovery
	if err := wait.PollImmediateUntil(time.Second, func() (bool, error) {
		crds, err := c.crdLister.List(labels.Everything())
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("failed to initially list CRDs: %v", err))
			return false, nil
		}
		for _, crd := range crds {
			for _, v := range crd.Spec.Versions {
				gv := schema.GroupVersion{Group: crd.Spec.Group, Version: v.Name}
				if err := c.sync(gv); err != nil {
					utilruntime.HandleError(fmt.Errorf("failed to initially sync CRD version %v: %v", gv, err))
					return false, nil
				}
			}
		}
		return true, nil
	}, stopCh); err == wait.ErrWaitTimeout {
		utilruntime.HandleError(fmt.Errorf("timed out waiting for discovery endpoint to initialize"))
		return
	} else if err != nil {
		panic(fmt.Errorf("unexpected error: %v", err))
	}
	close(synchedCh)

	// only start one worker thread since its a slow moving API
	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
}

func (c *DiscoveryController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *DiscoveryController) Run(stopCh <-chan struct{}, synchedCh chan<- struct{}) {
	defer utilruntime.HandleCrash() // 捕获并处理崩溃
	defer c.queue.ShutDown() // 关闭工作队列
	defer klog.Info("Shutting down DiscoveryController") // 记录日志，表示关闭 DiscoveryController

	klog.Info("Starting DiscoveryController") // 记录日志，表示启动 DiscoveryController

	// 等待缓存同步
	if !cache.WaitForCacheSync(stopCh, c.crdsSynced) {
		utilruntime.HandleError(fmt.Errorf("timed out waiting for caches to sync")) // 记录错误，表示等待缓存同步超时
		return
	}

	// 初始同步所有的分组版本，以确保提供完整的发现
	if err := wait.PollImmediateUntil(time.Second, func() (bool, error) {
		crds, err := c.crdLister.List(labels.Everything()) // 获取所有自定义资源定义列表
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("failed to initially list CRDs: %v", err)) // 记录错误，表示获取自定义资源定义列表失败
			return false, nil
		}
		for _, crd := range crds {
			for _, v := range crd.Spec.Versions {
				gv := schema.GroupVersion{Group: crd.Spec.Group, Version: v.Name} // 构建 GroupVersion 对象
				if err := c.sync(gv); err != nil {
					utilruntime.HandleError(fmt.Errorf("failed to initially sync CRD version %v: %v", gv, err)) // 记录错误，表示同步 CRD 版本失败
					return false, nil
				}
			}
		}
		return true, nil
	}, stopCh); err == wait.ErrWaitTimeout {
		utilruntime.HandleError(fmt.Errorf("timed out waiting for discovery endpoint to initialize")) // 记录错误，表示等待发现端点初始化超时
		return
	} else if err != nil {
		panic(fmt.Errorf("unexpected error: %v", err)) // 抛出异常，表示发生意外错误
	}
	close(synchedCh) // 关闭 synchedCh 通道，表示缓存同步完成

	// 只启动一个工作线程，因为该API的变化速度较慢
	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh // 等待停止信号
}

func (c *DiscoveryController) runWorker() {
	for c.processNextWorkItem() {
	}
}

// processNextWorkItem 处理队列中的一个键。当需要退出时返回 false。
func (c *DiscoveryController) processNextWorkItem() bool {
	key, quit := c.queue.Get() // 从队列中获取一个键
	if quit {
		return false
	}
	defer c.queue.Done(key) // 在函数退出时标记任务处理完成

	err := c.syncFn(key.(schema.GroupVersion)) // 同步指定的 GroupVersion
	if err == nil {
		c.queue.Forget(key) // 如果同步成功，则移除该键
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with: %v", key, err)) // 记录错误，表示同步失败
	c.queue.AddRateLimited(key) // 添加到有限速的队列中，以便稍后重新尝试

	return true
}

func (c *DiscoveryController) sync(version schema.GroupVersion) error {
	apiVersionsForDiscovery := []metav1.GroupVersionForDiscovery{} // 用于发现的 API 版本
	apiResourcesForDiscovery := []metav1.APIResource{} // 用于发现的 API 资源
	aggregatedApiResourcesForDiscovery := []apidiscoveryv2beta1.APIResourceDiscovery{} // 聚合的 API 资源
	versionsForDiscoveryMap := map[metav1.GroupVersion]bool{} // 用于发现的版本映射

	crds, err := c.crdLister.List(labels.Everything()) // 获取所有自定义资源定义列表
	if err != nil {
		return err
	}
	foundVersion := false
	foundGroup := false
	for _, crd := range crds {
		if !apiextensionshelpers.IsCRDConditionTrue(crd, apiextensionsv1.Established) {
			continue
		}

		if crd.Spec.Group != version.Group {
			continue
		}

		foundThisVersion := false
		var storageVersionHash string
		for _, v := range crd.Spec.Versions {
			if !v.Served {
				continue
			}
			// 如果有任何一个 Served 版本，表示该分组应该在发现中显示
			foundGroup = true

			gv := metav1.GroupVersion{Group: crd.Spec.Group, Version: v.Name}
			if !versionsForDiscoveryMap[gv] {
				versionsForDiscoveryMap[gv] = true
				apiVersionsForDiscovery = append(apiVersionsForDiscovery, metav1.GroupVersionForDiscovery{
					GroupVersion: crd.Spec.Group + "/" + v.Name,
					Version:      v.Name,
				})
			}
			if v.Name == version.Version {
				foundThisVersion = true
			}
			if v.Storage {
				storageVersionHash = discovery.StorageVersionHash(gv.Group, gv.Version, crd.Spec.Names.Kind)
			}
		}

		if !foundThisVersion {
			continue
		}
		foundVersion = true

		verbs := metav1.Verbs([]string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"})
		// 如果正在终止中，不允许一些动词
		if apiextensionshelpers.IsCRDConditionTrue(crd, apiextensionsv1.Terminating) {
			verbs = metav1.Verbs([]string{"delete", "deletecollection", "get", "list", "watch"})
		}

		apiResourcesForDiscovery = append(apiResourcesForDiscovery, metav1.APIResource{
			Name:               crd.Status.AcceptedNames.Plural,
			SingularName:       crd.Status.AcceptedNames.Singular,
			Namespaced:         crd.Spec.Scope == apiextensionsv1.NamespaceScoped,
			Kind:               crd.Status.AcceptedNames.Kind,
			Verbs:              verbs,
			ShortNames:         crd.Status.AcceptedNames.ShortNames,
			Categories:         crd.Status.AcceptedNames.Categories,
			StorageVersionHash: storageVersionHash,
		})

		subresources, err := apiextensionshelpers.GetSubresourcesForVersion(crd, version.Version)
		if err != nil {
			return err
		}

		if c.resourceManager != nil {
			var scope apidiscoveryv2beta1.ResourceScope
			if crd.Spec.Scope == apiextensionsv1.NamespaceScoped {
				scope = apidiscoveryv2beta1.ScopeNamespace
			} else {
				scope = apidiscoveryv2beta1.ScopeCluster
			}
			apiResourceDiscovery := apidiscoveryv2beta1.APIResourceDiscovery{
				Resource:         crd.Status.AcceptedNames.Plural,
				SingularResource: crd.Status.AcceptedNames.Singular,
				Scope:            scope,
				ResponseKind: &metav1.GroupVersionKind{
					Group:   version.Group,
					Version: version.Version,
					Kind:    crd.Status.AcceptedNames.Kind,
				},
				Verbs:      verbs,
				ShortNames: crd.Status.AcceptedNames.ShortNames,
				Categories: crd.Status.AcceptedNames.Categories,
			}
			if subresources != nil && subresources.Status != nil {
				apiResourceDiscovery.Subresources = append(apiResourceDiscovery.Subresources, apidiscoveryv2beta1.APISubresourceDiscovery{
					Subresource: "status",
					ResponseKind: &metav1.GroupVersionKind{
						Group:   version.Group,
						Version: version.Version,
						Kind:    crd.Status.AcceptedNames.Kind,
					},
					Verbs: metav1.Verbs([]string{"get", "patch", "update"}),
				})
			}
			if subresources != nil && subresources.Scale != nil {
				apiResourceDiscovery.Subresources = append(apiResourceDiscovery.Subresources, apidiscoveryv2beta1.APISubresourceDiscovery{
					Subresource: "scale",
					ResponseKind: &metav1.GroupVersionKind{
						Group:   autoscaling.GroupName,
						Version: "v1",
						Kind:    "Scale",
					},
					Verbs: metav1.Verbs([]string{"get", "patch", "update"}),
				})

			}
			aggregatedApiResourcesForDiscovery = append(aggregatedApiResourcesForDiscovery, apiResourceDiscovery)
		}

		if subresources != nil && subresources.Status != nil {
			apiResourcesForDiscovery = append(apiResourcesForDiscovery, metav1.APIResource{
				Name:       crd.Status.AcceptedNames.Plural + "/status",
				Namespaced: crd.Spec.Scope == apiextensionsv1.NamespaceScoped,
				Kind:       crd.Status.AcceptedNames.Kind,
				Verbs:      metav1.Verbs([]string{"get", "patch", "update"}),
			})
		}

		if subresources != nil && subresources.Scale != nil {
			apiResourcesForDiscovery = append(apiResourcesForDiscovery, metav1.APIResource{
				Group:      autoscaling.GroupName,
				Version:    "v1",
				Kind:       "Scale",
				Name:       crd.Status.AcceptedNames.Plural + "/scale",
				Namespaced: crd.Spec.Scope == apiextensionsv1.NamespaceScoped,
				Verbs:      metav1.Verbs([]string{"get", "patch", "update"}),
			})
		}
	}
	
    if !foundGroup {
        // 如果没有找到组，则执行以下操作：
        c.groupHandler.unsetDiscovery(version.Group) 
        // 取消设置版本的发现状态
        c.versionHandler.unsetDiscovery(version)
        // 取消设置资源管理器中的该组
        if c.resourceManager != nil {
            c.resourceManager.RemoveGroup(version.Group)
            // 如果资源管理器存在，则移除该组
        }
        return nil
        // 返回空值
    }

    sortGroupDiscoveryByKubeAwareVersion(apiVersionsForDiscovery)
    // 按照 kubeAware 版本对发现的 API 版本进行排序

    apiGroup := metav1.APIGroup{
        Name:     version.Group,
        Versions: apiVersionsForDiscovery,
        // 创建一个 APIGroup 结构体，包括名称和发现的 API 版本列表
        // 该组的首选版本为 apiVersionsForDiscovery 中的第一个版本
        PreferredVersion: apiVersionsForDiscovery[0],
    }

    c.groupHandler.setDiscovery(version.Group, discovery.NewAPIGroupHandler(Codecs, apiGroup))
    // 在组处理器中设置版本的发现状态为已发现，并使用给定的 Codecs 和 APIGroup 对象创建新的 APIGroupHandler

    if !foundVersion {
        // 如果没有找到版本，则执行以下操作：
        c.versionHandler.unsetDiscovery(version)
        // 取消设置版本的发现状态

        if c.resourceManager != nil {
            c.resourceManager.RemoveGroupVersion(metav1.GroupVersion{
                Group:   version.Group,
                Version: version.Version,
            })
            // 如果资源管理器存在，则移除指定的组和版本
        }
        return nil
        // 返回空值
    }

    c.versionHandler.setDiscovery(version, discovery.NewAPIVersionHandler(Codecs, version, discovery.APIResourceListerFunc(func() []metav1.APIResource {
        return apiResourcesForDiscovery
    })))
    // 在版本处理器中设置版本的发现状态为已发现，并使用给定的 Codecs、版本和 APIResourceListerFunc 创建新的 APIVersionHandler

    sort.Slice(aggregatedApiResourcesForDiscovery[:], func(i, j int) bool {
        return aggregatedApiResourcesForDiscovery[i].Resource < aggregatedApiResourcesForDiscovery[j].Resource
    })
    // 按照 API 资源的名称对发现的聚合 API 资源进行排序

    if c.resourceManager != nil {
        c.resourceManager.AddGroupVersion(version.Group, apidiscoveryv2beta1.APIVersionDiscovery{
            Freshness: apidiscoveryv2beta1.DiscoveryFreshnessCurrent,
            Version:   version.Version,
            Resources: aggregatedApiResourcesForDiscovery,
        })
        // 如果资源管理器存在，则添加指定组和版本的 APIVersionDiscovery 到资源管理器中
        // 设置 APIVersionDiscovery 的 Freshness、Version 和 Resources 字段
        // Freshness 设置为当前，Version 设置为给定的版本，Resources 设置为聚合的 API 资源列表

        c.resourceManager.SetGroupVersionPriority(metav1.GroupVersion(version), 1000, 100)
        // 设置指定组和版本的优先级为 1000 和 100（默认优先级）
    }
    return nil
    // 返回空值
}
```

#### NamingConditionController

管理自定义资源定义（Custom Resource Definition，CRD）的命名条件。它确保每个CRD在创建或更新时都具有唯一的名称，并且在命名冲突时能够解决冲突。

```GO
// 这个控制器用于保留名称。为了避免冲突，请确保每次只运行一个 worker 实例。
// 这个限制可能会在以后解除，但先从简单的开始。
type NamingConditionController struct {
	crdClient client.CustomResourceDefinitionsGetter
    crdLister listers.CustomResourceDefinitionLister
    crdSynced cache.InformerSynced
    // crdMutationCache 支持我们的 lister，并跟踪已提交的更新，以避免竞争写入/查找循环。默认情况下，它有100个插槽，因此不太可能溢出。
    // 如果在实际情况中发现命名冲突，则需要重新审视这一点。
	crdMutationCache cache.MutationCache
	// 为了允许测试时进行注入。
    syncFn func(key string) error

    queue workqueue.RateLimitingInterface
}

// NewNamingConditionController 是 NamingConditionController 的构造函数。
func NewNamingConditionController(
crdInformer informers.CustomResourceDefinitionInformer,
crdClient client.CustomResourceDefinitionsGetter,
) *NamingConditionController {
    c := &NamingConditionController{
    crdClient: crdClient,
    crdLister: crdInformer.Lister(),
    crdSynced: crdInformer.Informer().HasSynced,
    queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "crd_naming_condition_controller"),
    }
    informerIndexer := crdInformer.Informer().GetIndexer()
    c.crdMutationCache = cache.NewIntegerResourceVersionMutationCache(informerIndexer, informerIndexer, 60*time.Second, false)

    crdInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc:    c.addCustomResourceDefinition,
        UpdateFunc: c.updateCustomResourceDefinition,
        DeleteFunc: c.deleteCustomResourceDefinition,
    })

    c.syncFn = c.sync

    return c
}

func (c *NamingConditionController) addCustomResourceDefinition(obj interface{}) {
	castObj := obj.(*apiextensionsv1.CustomResourceDefinition)
	klog.V(4).Infof("Adding %s", castObj.Name)
	c.enqueue(castObj)
}

func (c *NamingConditionController) updateCustomResourceDefinition(obj, _ interface{}) {
	castObj := obj.(*apiextensionsv1.CustomResourceDefinition)
	klog.V(4).Infof("Updating %s", castObj.Name)
	c.enqueue(castObj)
}

func (c *NamingConditionController) deleteCustomResourceDefinition(obj interface{}) {
	castObj, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Couldn't get object from tombstone %#v", obj)
			return
		}
		castObj, ok = tombstone.Obj.(*apiextensionsv1.CustomResourceDefinition)
		if !ok {
			klog.Errorf("Tombstone contained object that is not expected %#v", obj)
			return
		}
	}
	klog.V(4).Infof("Deleting %q", castObj.Name)
	c.enqueue(castObj)
}

func (c *NamingConditionController) enqueue(obj *apiextensionsv1.CustomResourceDefinition) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %#v: %v", obj, err))
		return
	}

	c.queue.Add(key)
}

func (c *NamingConditionController) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Info("Starting NamingConditionController")
	defer klog.Info("Shutting down NamingConditionController")

	if !cache.WaitForCacheSync(stopCh, c.crdSynced) {
		return
	}

	// only start one worker thread since its a slow moving API and the naming conflict resolution bits aren't thread-safe
	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
}


func (c *NamingConditionController) runWorker() {
	for c.processNextWorkItem() {
	}
}

// processNextWorkItem deals with one key off the queue.  It returns false when it's time to quit.
func (c *NamingConditionController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.syncFn(key.(string))
	if err == nil {
		c.queue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with: %v", key, err))
	c.queue.AddRateLimited(key)

	return true
}

func (c *NamingConditionController) sync(key string) error {
	inCustomResourceDefinition, err := c.crdLister.Get(key)
	// 获取指定键对应的自定义资源定义对象
	if apierrors.IsNotFound(err) {
		// 如果找不到该对象，则执行以下操作：
		// 自定义资源定义已被删除并释放了其名称。
		// 重新考虑同一组中的所有其他自定义资源定义对象。
		if err := c.requeueAllOtherGroupCRDs(key); err != nil {
			return err
		}
		return nil
	}
	if err != nil {
		return err
	}

	if equality.Semantic.DeepEqual(inCustomResourceDefinition.Spec.Names, inCustomResourceDefinition.Status.AcceptedNames) {
		// 如果规范和状态的名称相同，则跳过名称检查。
		return nil
	}

	acceptedNames, namingCondition, establishedCondition := c.calculateNamesAndConditions(inCustomResourceDefinition)
	// 计算接受的名称和条件

	if reflect.DeepEqual(inCustomResourceDefinition.Status.AcceptedNames, acceptedNames) &&
		apiextensionshelpers.IsCRDConditionEquivalent(&namingCondition, apiextensionshelpers.FindCRDCondition(inCustomResourceDefinition, apiextensionsv1.NamesAccepted)) {
		// 如果接受的名称和 NamesAccepted 条件没有更改，则无需进行任何操作。
		return nil
	}

	crd := inCustomResourceDefinition.DeepCopy()
	crd.Status.AcceptedNames = acceptedNames
	apiextensionshelpers.SetCRDCondition(crd, namingCondition)
	apiextensionshelpers.SetCRDCondition(crd, establishedCondition)
	// 更新自定义资源定义对象的状态和条件

	updatedObj, err := c.crdClient.CustomResourceDefinitions().UpdateStatus(context.TODO(), crd, metav1.UpdateOptions{})
	// 更新自定义资源定义对象的状态
	if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		// 如果对象已被删除或在此期间发生更改，则会再次调用此函数
		return nil
	}
	if err != nil {
		return err
	}

	c.crdMutationCache.Mutation(updatedObj)
	// 更新缓存中的自定义资源定义对象

	if err := c.requeueAllOtherGroupCRDs(key); err != nil {
		// 更新完状态后，重新触发同一组中的所有其他自定义资源定义对象的处理
		return err
	}

	return nil
}

func (c *NamingConditionController) getAcceptedNamesForGroup(group string) (allResources sets.String, allKinds sets.String) {
	allResources = sets.String{}
	allKinds = sets.String{}

	// 获取所有的自定义资源定义对象
	list, err := c.crdLister.List(labels.Everything())
	if err != nil {
		panic(err)
	}

	for _, curr := range list {
		if curr.Spec.Group != group {
			continue
		}

		// 对于每个自定义资源定义对象，检查是否有更近期的变异缓存条目，
		// 确保如果我们在更新和运行时出现紧密循环，变异缓存将显示我们刚刚更新的对象的版本。
		item := curr
		obj, exists, err := c.crdMutationCache.GetByKey(curr.Name)
		if exists && err == nil {
			item = obj.(*apiextensionsv1.CustomResourceDefinition)
		}

		// 将资源名称和种类插入到相应的集合中
		allResources.Insert(item.Status.AcceptedNames.Plural)
		allResources.Insert(item.Status.AcceptedNames.Singular)
		allResources.Insert(item.Status.AcceptedNames.ShortNames...)

		allKinds.Insert(item.Status.AcceptedNames.Kind)
		allKinds.Insert(item.Status.AcceptedNames.ListKind)
	}

	return allResources, allKinds
}

func (c *NamingConditionController) calculateNamesAndConditions(in *apiextensionsv1.CustomResourceDefinition) (apiextensionsv1.CustomResourceDefinitionNames, apiextensionsv1.CustomResourceDefinitionCondition, apiextensionsv1.CustomResourceDefinitionCondition) {
	// 获取已经被占用的名称
	allResources, allKinds := c.getAcceptedNamesForGroup(in.Spec.Group)

	// 初始化 namesAcceptedCondition
	namesAcceptedCondition := apiextensionsv1.CustomResourceDefinitionCondition{
		Type:   apiextensionsv1.NamesAccepted,
		Status: apiextensionsv1.ConditionUnknown,
	}

	// 获取请求的名称和已接受的名称
	requestedNames := in.Spec.Names
	acceptedNames := in.Status.AcceptedNames
	newNames := in.Status.AcceptedNames

	// 检查每个名称是否存在不匹配。如果规范和状态之间存在不匹配，尝试进行解决冲突。
	// 继续处理错误，以便状态是可能的最佳匹配。
	if err := equalToAcceptedOrFresh(requestedNames.Plural, acceptedNames.Plural, allResources); err != nil {
		namesAcceptedCondition.Status = apiextensionsv1.ConditionFalse
		namesAcceptedCondition.Reason = "PluralConflict"
		namesAcceptedCondition.Message = err.Error()
	} else {
		newNames.Plural = requestedNames.Plural
	}
	if err := equalToAcceptedOrFresh(requestedNames.Singular, acceptedNames.Singular, allResources); err != nil {
		namesAcceptedCondition.Status = apiextensionsv1.ConditionFalse
		namesAcceptedCondition.Reason = "SingularConflict"
		namesAcceptedCondition.Message = err.Error()
	} else {
		newNames.Singular = requestedNames.Singular
	}
	if !reflect.DeepEqual(requestedNames.ShortNames, acceptedNames.ShortNames) {
		errs := []error{}
		existingShortNames := sets.NewString(acceptedNames.ShortNames...)
		for _, shortName := range requestedNames.ShortNames {
			// 如果 shortName 已经是我们的，那么是合法的
			if existingShortNames.Has(shortName) {
				continue
			}
			if err := equalToAcceptedOrFresh(shortName, "", allResources); err != nil {
				errs = append(errs, err)
			}
		}
		if err := utilerrors.NewAggregate(errs); err != nil {
			namesAcceptedCondition.Status = apiextensionsv1.ConditionFalse
			namesAcceptedCondition.Reason = "ShortNamesConflict"
			namesAcceptedCondition.Message = err.Error()
		} else {
			newNames.ShortNames = requestedNames.ShortNames
		}
	}

	if err := equalToAcceptedOrFresh(requestedNames.Kind, acceptedNames.Kind, allKinds); err != nil {
		namesAcceptedCondition.Status = apiextensionsv1.ConditionFalse
		namesAcceptedCondition.Reason = "KindConflict"
		namesAcceptedCondition.Message = err.Error()
	} else {
		newNames.Kind = requestedNames.Kind
	}
	if err := equalToAcceptedOrFresh(requestedNames.ListKind, acceptedNames.ListKind, allKinds); err != nil {
		namesAcceptedCondition.Status = apiextensionsv1.ConditionFalse
		namesAcceptedCondition.Reason = "ListKindConflict"
		namesAcceptedCondition.Message = err.Error()
	} else {
		newNames.ListKind = requestedNames.ListKind
	}

	newNames.Categories = requestedNames.Categories

	// 如果条件未更改，则我们的名称必须是有效的。
	if namesAcceptedCondition.Status == apiextensionsv1.ConditionUnknown {
		namesAcceptedCondition.Status = apiextensionsv1.ConditionTrue
		namesAcceptedCondition.Reason = "NoConflicts"
		namesAcceptedCondition.Message = "no conflicts found"
	}

	// 初始化 establishedCondition 为 false，然后在建立控制器中将其设置为 true。
	// 当建立控制器通过共享的 informer 收到 NamesAccepted 条件时，将会看到它。
	// 此时，API 端点处理程序将提供端点，避免竞争，这是我们在这里设置 Established 为 true 时遇到的竞争。
	establishedCondition := apiextensionsv1.CustomResourceDefinitionCondition{
		Type:    apiextensionsv1.Established,
		Status:  apiextensionsv1.ConditionFalse,
		Reason:  "NotAccepted",
		Message: "not all names are accepted",
	}
	if old := apiextensionshelpers.FindCRDCondition(in, apiextensionsv1.Established); old != nil {
		establishedCondition = *old
	}
	if establishedCondition.Status != apiextensionsv1.ConditionTrue && namesAcceptedCondition.Status == apiextensionsv1.ConditionTrue {
		establishedCondition = apiextensionsv1.CustomResourceDefinitionCondition{
			Type:    apiextensionsv1.Established,
			Status:  apiextensionsv1.ConditionFalse,
			Reason:  "Installing",
			Message: "the initial names have been accepted",
		}
	}

	return newNames, namesAcceptedCondition, establishedCondition
}

func (c *NamingConditionController) requeueAllOtherGroupCRDs(name string) error {
	// 拆分名称中的组名
	pluralGroup := strings.SplitN(name, ".", 2)
	// 获取所有的自定义资源定义对象
	list, err := c.crdLister.List(labels.Everything())
	if err != nil {
		return err
	}
	for _, curr := range list {
		// 如果当前自定义资源定义对象的组名与目标组名相同且名称不同，则将其加入队列
		if curr.Spec.Group == pluralGroup[1] && curr.Name != name {
			c.queue.Add(curr.Name)
		}
	}
	return nil
}
```

#### ConditionController

它负责与CustomResourceDefinition对象进行交互，并根据对象的添加、更新和删除事件来执行相应的操作。

1. 维护CustomResourceDefinition对象的条件状态。
2. 监听CustomResourceDefinition对象的事件（添加、更新、删除）。
3. 将CustomResourceDefinition对象添加到工作队列中进行处理。
4. 在处理队列中的工作项时，根据CustomResourceDefinition对象的状态执行相应的操作。
5. 保持最后一次生成的条件代数（generation）的记录，以避免在高可用性环境中不同版本的apiextensions-apiservers竞争正确的消息。

```go
// ConditionController维护NonStructuralSchema条件。
type ConditionController struct {
	crdClient client.CustomResourceDefinitionsGetter // 用于获取CustomResourceDefinition的客户端
    crdLister listers.CustomResourceDefinitionLister // 用于列举CustomResourceDefinition的列表
    crdSynced cache.InformerSynced // 用于同步CustomResourceDefinition的缓存

    // 用于测试的注入功能
    syncFn func(key string) error

    queue workqueue.RateLimitingInterface // 用于处理工作项的队列

    // 上次生成该控制器更新的条件的CRD名称（避免HA中的两个不同版本的apiextensions-apiservers争夺正确的消息）
    lastSeenGenerationLock sync.Mutex
    lastSeenGeneration     map[string]int64 // 记录每个CRD的最后一次生成的代数
}

// NewConditionController构造一个非结构化模式条件控制器。
func NewConditionController(
    crdInformer informers.CustomResourceDefinitionInformer, // CustomResourceDefinition的Informer
    crdClient client.CustomResourceDefinitionsGetter, // 获取CustomResourceDefinition的客户端
) *ConditionController {
    c := &ConditionController{
        crdClient: crdClient,
        crdLister: crdInformer.Lister(),
        crdSynced: crdInformer.Informer().HasSynced,
        queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "non_structural_schema_condition_controller"),
        lastSeenGeneration: map[string]int64{},
    }
    // 为CustomResourceDefinition的Informer添加事件处理程序
    crdInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc:    c.addCustomResourceDefinition,
        UpdateFunc: c.updateCustomResourceDefinition,
        DeleteFunc: c.deleteCustomResourceDefinition,
    })

    c.syncFn = c.sync

    return c
}

// 将CustomResourceDefinition对象添加到队列中
func (c *ConditionController) enqueue(obj *apiextensionsv1.CustomResourceDefinition) {
key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
    if err != nil {
        utilruntime.HandleError(fmt.Errorf("couldn't get key for object %#v: %v", obj, err))
        return
    }

    c.queue.Add(key)
}
// 添加CustomResourceDefinition的事件处理函数
func (c *ConditionController) addCustomResourceDefinition(obj interface{}) {
    castObj := obj.(*apiextensionsv1.CustomResourceDefinition)
    klog.V(4).Infof("Adding %s", castObj.Name)
    c.enqueue(castObj)
}

// 更新CustomResourceDefinition的事件处理函数
func (c *ConditionController) updateCustomResourceDefinition(obj, _ interface{}) {
    castObj := obj.(*apiextensionsv1.CustomResourceDefinition)
    klog.V(4).Infof("Updating %s", castObj.Name)
    c.enqueue(castObj)
}

// 删除CustomResourceDefinition的事件处理函数
func (c *ConditionController) deleteCustomResourceDefinition(obj interface{}) {
	castObj, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Couldn't get object from tombstone %#v", obj)
			return
		}
		castObj, ok = tombstone.Obj.(*apiextensionsv1.CustomResourceDefinition)
		if !ok {
			klog.Errorf("Tombstone contained object that is not expected %#v", obj)
			return
		}
	}

	c.lastSeenGenerationLock.Lock()
	defer c.lastSeenGenerationLock.Unlock()
	delete(c.lastSeenGeneration, castObj.Name)
}

// Run starts the controller.
func (c *ConditionController) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting NonStructuralSchemaConditionController")
	defer klog.Infof("Shutting down NonStructuralSchemaConditionController")

	if !cache.WaitForCacheSync(stopCh, c.crdSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *ConditionController) runWorker() {
	for c.processNextWorkItem() {
	}
}

// processNextWorkItem deals with one key off the queue.  It returns false when it's time to quit.
func (c *ConditionController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.syncFn(key.(string))
	if err == nil {
		c.queue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with: %v", key, err))
	c.queue.AddRateLimited(key)

	return true
}

func (c *ConditionController) sync(key string) error {
	// 同步方法开始，传入一个 key 字符串作为参数

	// 获取指定 key 对应的 CustomResourceDefinition
	inCustomResourceDefinition, err := c.crdLister.Get(key)
	if apierrors.IsNotFound(err) {
		// 如果找不到对应的 CustomResourceDefinition，则返回空，表示无需处理
		return nil
	}
	if err != nil {
		// 如果发生其他错误，则返回错误
		return err
	}

	// 避免对相同生成版本进行重复计算
	c.lastSeenGenerationLock.Lock()
	lastSeen, seenBefore := c.lastSeenGeneration[inCustomResourceDefinition.Name]
	c.lastSeenGenerationLock.Unlock()
	if seenBefore && inCustomResourceDefinition.Generation <= lastSeen {
		// 如果已经处理过该生成版本，则返回空，无需再次处理
		return nil
	}

	// 检查旧的条件
	cond := calculateCondition(inCustomResourceDefinition)
	old := apiextensionshelpers.FindCRDCondition(inCustomResourceDefinition, apiextensionsv1.NonStructuralSchema)

	if cond == nil && old == nil {
		// 如果旧的条件和新的条件都为空，则返回空，无需更新
		return nil
	}
	if cond != nil && old != nil && old.Status == cond.Status && old.Reason == cond.Reason && old.Message == cond.Message {
		// 如果旧的条件和新的条件相同，则返回空，无需更新
		return nil
	}

	// 更新条件
	crd := inCustomResourceDefinition.DeepCopy()
	if cond == nil {
		// 如果新的条件为空，则移除旧的条件
		apiextensionshelpers.RemoveCRDCondition(crd, apiextensionsv1.NonStructuralSchema)
	} else {
		// 否则，更新新的条件
		cond.LastTransitionTime = metav1.NewTime(time.Now())
		apiextensionshelpers.SetCRDCondition(crd, *cond)
	}

	_, err = c.crdClient.CustomResourceDefinitions().UpdateStatus(context.TODO(), crd, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		// 如果在更新过程中发生删除或冲突，则返回空，表示稍后会再次调用该方法
		return nil
	}
	if err != nil {
		// 如果发生其他错误，则返回错误
		return err
	}

	// 存储生成版本，以避免对相同生成版本的重复更新（在高可用环境中可能导致 API 服务器竞争）
	c.lastSeenGenerationLock.Lock()
	defer c.lastSeenGenerationLock.Unlock()
	c.lastSeenGeneration[crd.Name] = crd.Generation

	return nil
}

func calculateCondition(in *apiextensionsv1.CustomResourceDefinition) *apiextensionsv1.CustomResourceDefinitionCondition {
	// 计算条件函数，根据 CustomResourceDefinition 计算出相应的条件

	// 初始化条件
	cond := &apiextensionsv1.CustomResourceDefinitionCondition{
		Type:   apiextensionsv1.NonStructuralSchema,
		Status: apiextensionsv1.ConditionUnknown,
	}

	// 初始化错误列表
	allErrs := field.ErrorList{}

	if in.Spec.PreserveUnknownFields {
		// 如果 PreserveUnknownFields 为 true，则添加错误到错误列表
		allErrs = append(allErrs, field.Invalid(field.NewPath("spec", "preserveUnknownFields"),
			in.Spec.PreserveUnknownFields,
			fmt.Sprint("must be false")))
	}

	for i, v := range in.Spec.Versions {
		if v.Schema == nil || v.Schema.OpenAPIV3Schema == nil {
			// 如果版本的 Schema 为空，则继续下一个版本的检查
			continue
		}

		internalSchema := &apiextensionsinternal.CustomResourceValidation{}
		if err := apiextensionsv1.Convert_v1_CustomResourceValidation_To_apiextensions_CustomResourceValidation(v.Schema, internalSchema, nil); err != nil {
			// 将 CRD 验证转换为内部版本时发生错误，记录错误并继续下一个版本的检查
			klog.Errorf("failed to convert CRD validation to internal version: %v", err)
			continue
		}
		s, err := schema.NewStructural(internalSchema.OpenAPIV3Schema)
		if err != nil {
			// 创建结构化 Schema 时发生错误，设置条件的 Reason 和 Message，并返回该条件
			cond.Reason = "StructuralError"
			cond.Message = fmt.Sprintf("failed to check validation schema for version %s: %v", v.Name, err)
			return cond
		}

		pth := field.NewPath("spec", "versions").Index(i).Child("schema", "openAPIV3Schema")

		// 验证结构化 Schema，将错误添加到错误列表
		allErrs = append(allErrs, schema.ValidateStructural(pth, s)...)
	}

	if len(allErrs) == 0 {
		// 如果错误列表为空，则返回空，表示条件无需更新
		return nil
	}

	// 设置条件的 Status、Reason 和 Message
	cond.Status = apiextensionsv1.ConditionTrue
	cond.Reason = "Violations"
	cond.Message = allErrs.ToAggregate().Error()

	return cond
}
```

#### KubernetesAPIApprovalPolicyConformantConditionController

KubernetesAPIApprovalPolicyConformantConditionController是一个控制器，用于维护和管理KubernetesAPIApprovalPolicyConformant条件。

1. 在构造函数中，它接收一个CustomResourceDefinitionInformer和一个CustomResourceDefinitionsGetter，用于获取自定义资源定义的信息。
2. 控制器具有一个工作队列（queue），用于存储需要处理的自定义资源定义对象的键。
3. 控制器在创建时注册了一组事件处理函数，用于处理CustomResourceDefinition对象的添加、更新和删除事件。
4. 控制器的主要功能是将CustomResourceDefinition对象添加到工作队列中，以便后续处理。
5. 控制器还具有同步功能（syncFn），在需要时可以执行同步操作。
6. 控制器使用了一些辅助函数，例如enqueue函数用于将CustomResourceDefinition对象添加到工作队列中。

```GO
// KubernetesAPIApprovalPolicyConformantConditionController维护了KubernetesAPIApprovalPolicyConformant条件。
type KubernetesAPIApprovalPolicyConformantConditionController struct {
    crdClient client.CustomResourceDefinitionsGetter
    crdLister listers.CustomResourceDefinitionLister
    crdSynced cache.InformerSynced
    syncFn func(key string) error
    queue workqueue.RateLimitingInterface
    lastSeenProtectedAnnotationLock sync.Mutex
    lastSeenProtectedAnnotation map[string]string
}

// NewKubernetesAPIApprovalPolicyConformantConditionController构造一个KubernetesAPIApprovalPolicyConformant模式条件控制器。
func NewKubernetesAPIApprovalPolicyConformantConditionController(
    crdInformer informers.CustomResourceDefinitionInformer,
    crdClient client.CustomResourceDefinitionsGetter,
) *KubernetesAPIApprovalPolicyConformantConditionController {
    c := &KubernetesAPIApprovalPolicyConformantConditionController{
        crdClient: crdClient,
        crdLister: crdInformer.Lister(),
        crdSynced: crdInformer.Informer().HasSynced,
        queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "kubernetes_api_approval_conformant_condition_controller"),
        lastSeenProtectedAnnotation: map[string]string{},
	}
    crdInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc:    c.addCustomResourceDefinition,
        UpdateFunc: c.updateCustomResourceDefinition,
        DeleteFunc: c.deleteCustomResourceDefinition,
    })

    c.syncFn = c.sync

    return c
}

func (c *KubernetesAPIApprovalPolicyConformantConditionController) addCustomResourceDefinition(obj interface{}) {
    castObj := obj.(*apiextensionsv1.CustomResourceDefinition)
    klog.V(4).Infof("Adding %s", castObj.Name)
    c.enqueue(castObj)
}

func (c *KubernetesAPIApprovalPolicyConformantConditionController) updateCustomResourceDefinition(obj, _ interface{}) {
    castObj := obj.(*apiextensionsv1.CustomResourceDefinition)
    klog.V(4).Infof("Updating %s", castObj.Name)
    c.enqueue(castObj)
}

func (c *KubernetesAPIApprovalPolicyConformantConditionController) deleteCustomResourceDefinition(obj interface{}) {
    castObj, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
    if !ok {
        tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
        if !ok {
            klog.Errorf("Couldn't get object from tombstone %#v", obj)
        	return
        }
        castObj, ok = tombstone.Obj.(*apiextensionsv1.CustomResourceDefinition)
        if !ok {
            klog.Errorf("Tombstone contained object that is not expected %#v", obj)
            return
        }
    }
    rotectedAnnotationLock.Lock()
    defer c.lastSeenProtectedAnnotationLock.Unlock()
    delete(c.lastSeenProtectedAnnotation, castObj.Name)
}

func (c *KubernetesAPIApprovalPolicyConformantConditionController) enqueue(obj *apiextensionsv1.CustomResourceDefinition) {
    key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
    if err != nil {
        utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %#v: %v", obj, err))
        return
    }

    c.queue.Add(key)
}

// Run starts the controller.
func (c *KubernetesAPIApprovalPolicyConformantConditionController) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting KubernetesAPIApprovalPolicyConformantConditionController")
	defer klog.Infof("Shutting down KubernetesAPIApprovalPolicyConformantConditionController")

	if !cache.WaitForCacheSync(stopCh, c.crdSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *KubernetesAPIApprovalPolicyConformantConditionController) runWorker() {
	for c.processNextWorkItem() {
	}
}

// processNextWorkItem deals with one key off the queue.  It returns false when it's time to quit.
func (c *KubernetesAPIApprovalPolicyConformantConditionController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.syncFn(key.(string))
	if err == nil {
		c.queue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with: %v", key, err))
	c.queue.AddRateLimited(key)

	return true
}

func (c *KubernetesAPIApprovalPolicyConformantConditionController) sync(key string) error {
	// sync方法用于同步自定义资源定义的状态，参数key表示要同步的资源定义的键

	inCustomResourceDefinition, err := c.crdLister.Get(key)
	// 通过键获取自定义资源定义对象，并将结果赋值给inCustomResourceDefinition
	if apierrors.IsNotFound(err) {
		// 如果资源定义不存在，则返回nil
		return nil
	}
	if err != nil {
		// 如果发生错误，则返回错误
		return err
	}

	// 避免对相同注释进行重复计算
	protectionAnnotationValue := inCustomResourceDefinition.Annotations[apiextensionsv1.KubeAPIApprovedAnnotation]
	// 获取资源定义的注释中的"KubeAPIApproved"注释的值
	c.lastSeenProtectedAnnotationLock.Lock()
	// 加锁，确保操作的原子性
	lastSeen, seenBefore := c.lastSeenProtectedAnnotation[inCustomResourceDefinition.Name]
	// 获取最后一次见到的保护注释的值以及是否之前见过
	c.lastSeenProtectedAnnotationLock.Unlock()
	// 解锁
	if seenBefore && protectionAnnotationValue == lastSeen {
		// 如果之前见过该注释且注释的值与最后一次见到的值相同，则返回nil，无需进行更新
		return nil
	}

	// 检查旧条件
	cond := calculateCondition(inCustomResourceDefinition)
	// 调用calculateCondition函数计算新的KubernetesAPIApprovalPolicyConformant条件
	if cond == nil {
		// 如果计算得到的条件为空，则表示无需删除条件，返回nil
		return nil
	}
	old := apihelpers.FindCRDCondition(inCustomResourceDefinition, apiextensionsv1.KubernetesAPIApprovalPolicyConformant)
	// 查找资源定义中已存在的KubernetesAPIApprovalPolicyConformant条件

	// 如果所有条件细节都相同，则不进行写入
	if old != nil && old.Status == cond.Status && old.Reason == cond.Reason && old.Message == cond.Message {
		// 如果已存在的条件与新计算的条件相同，则返回nil，无需进行更新
		return nil
	}

	// 更新条件
	crd := inCustomResourceDefinition.DeepCopy()
	// 对资源定义进行深拷贝，以避免修改原始对象
	apihelpers.SetCRDCondition(crd, *cond)
	// 使用新的条件更新资源定义

	_, err = c.crdClient.CustomResourceDefinitions().UpdateStatus(context.TODO(), crd, metav1.UpdateOptions{})
	// 使用更新后的资源定义对象更新资源定义的状态
	if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		// 如果资源定义在更新过程中被删除或修改，则返回nil，稍后会再次调用sync方法进行同步
		return nil
	}
	if err != nil {
		// 如果发生其他错误，则返回错误
		return err
	}

	// 存储注释，以避免对相同注释进行重复更新（以及在HA环境中可能的API服务器竞争）
	c.lastSeenProtectedAnnotationLock.Lock()
	// 加锁，确保操作的原子性
	defer c.lastSeenProtectedAnnotationLock.Unlock()
	// 在函数返回前解锁
	c.lastSeenProtectedAnnotation[crd.Name] = protectionAnnotationValue
	// 将最后一次见到的保护注释的值存储起来

	return nil
}

// calculateCondition函数确定新的KubernetesAPIApprovalPolicyConformant条件
func calculateCondition(crd *apiextensionsv1.CustomResourceDefinition) *apiextensionsv1.CustomResourceDefinitionCondition {
	// calculateCondition函数用于根据自定义资源定义计算新的KubernetesAPIApprovalPolicyConformant条件
	if !apihelpers.IsProtectedCommunityGroup(crd.Spec.Group) {
		// 如果资源定义的Group不受保护，则返回nil
		return nil
	}

	approvalState, reason := apihelpers.GetAPIApprovalState(crd.Annotations)
	// 获取资源定义的注释中的APIApprovalState和原因
	switch approvalState {
	case apihelpers.APIApprovalInvalid:
		// 如果APIApprovalState为Invalid，则返回ConditionFalse和相应的原因和消息
		return &apiextensionsv1.CustomResourceDefinitionCondition{
			Type:    apiextensionsv1.KubernetesAPIApprovalPolicyConformant,
			Status:  apiextensionsv1.ConditionFalse,
			Reason:  "InvalidAnnotation",
			Message: reason,
		}
	case apihelpers.APIApprovalMissing:
		// 如果APIApprovalState为Missing，则返回ConditionFalse和相应的原因和消息
		return &apiextensionsv1.CustomResourceDefinitionCondition{
			Type:    apiextensionsv1.KubernetesAPIApprovalPolicyConformant,
			Status:  apiextensionsv1.ConditionFalse,
			Reason:  "MissingAnnotation",
			Message: reason,
		}
	case apihelpers.APIApproved:
		// 如果APIApprovalState为Approved，则返回ConditionTrue和相应的原因和消息
		return &apiextensionsv1.CustomResourceDefinitionCondition{
			Type:    apiextensionsv1.KubernetesAPIApprovalPolicyConformant,
			Status:  apiextensionsv1.ConditionTrue,
			Reason:  "ApprovedAnnotation",
			Message: reason,
		}
	case apihelpers.APIApprovalBypassed:
		// 如果APIApprovalState为Bypassed，则返回ConditionFalse和相应的原因和消息
		return &apiextensionsv1.CustomResourceDefinitionCondition{
			Type:    apiextensionsv1.KubernetesAPIApprovalPolicyConformant,
			Status:  apiextensionsv1.ConditionFalse,
			Reason:  "UnapprovedAnnotation",
			Message: reason,
		}
	default:
		// 其他情况返回ConditionUnknown和相应的原因和消息
		return &apiextensionsv1.CustomResourceDefinitionCondition{
			Type:    apiextensionsv1.KubernetesAPIApprovalPolicyConformant,
			Status:  apiextensionsv1.ConditionUnknown,
			Reason:  "UnknownAnnotation",
			Message: reason,
		}
	}
}
```

#### CRDFinalizer

CRDFinalizer是一个控制器，用于完成自定义资源定义（CRD）的最终操作。它的作用是在CRD被删除时，删除与之关联的所有自定义资源（CR）。

1. 监听CRD的事件：它通过注册为CRD的事件处理程序，监听CRD的添加和更新事件。
2. 处理CRD的添加事件：当检测到添加了一个新的CRD时，CRDFinalizer会检查该CRD是否具有指定的Finalizer，并且已被标记为删除。如果满足这些条件，它将将CRD对象添加到队列中。
3. 处理CRD的更新事件：当检测到CRD发生更新时，CRDFinalizer会检查CRD是否仍处于未删除状态，并且未完成最终操作。如果满足这些条件，并且CRD的资源版本没有变化，它将将CRD对象添加到队列中。如果资源版本发生变化，它会将CRD对象添加到队列中，以确保进行同步操作。
4. 将CRD对象加入队列：CRDFinalizer使用队列来管理要进行最终操作的CRD对象。它将CRD对象的键（通过缓存的删除处理函数生成）添加到队列中。

```GO
// CRDFinalizer是一个控制器，通过删除与之关联的所有CR来完成CRD的最终操作。
type CRDFinalizer struct {
    crdClient client.CustomResourceDefinitionsGetter
    crClientGetter CRClientGetter
    crdLister listers.CustomResourceDefinitionLister
    crdSynced cache.InformerSynced
    // 为了测试目的，允许注入syncFn函数。
    syncFn func(key string) error
    queue workqueue.RateLimitingInterface
}

// CRClientGetter知道如何为给定的CRD UID获取ListerCollectionDeleter。
type CRClientGetter interface {
    // GetCustomResourceListerCollectionDeleter获取给定CRD UID的ListerCollectionDeleter。
    GetCustomResourceListerCollectionDeleter(crd *apiextensionsv1.CustomResourceDefinition) (ListerCollectionDeleter, error)
}

// NewCRDFinalizer创建一个新的CRDFinalizer。
func NewCRDFinalizer(
    crdInformer informers.CustomResourceDefinitionInformer,
    crdClient client.CustomResourceDefinitionsGetter,
    crClientGetter CRClientGetter,
) *CRDFinalizer {
    c := &CRDFinalizer{
        crdClient: crdClient,
        crdLister: crdInformer.Lister(),
        crdSynced: crdInformer.Informer().HasSynced,
        crClientGetter: crClientGetter,
        queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "crd_finalizer"),
    }
    crdInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc:    c.addCustomResourceDefinition,
        UpdateFunc: c.updateCustomResourceDefinition,
    })

    c.syncFn = c.sync

    return c
}

// addCustomResourceDefinition是一个事件处理函数，用于处理添加CustomResourceDefinition事件。
func (c *CRDFinalizer) addCustomResourceDefinition(obj interface{}) {
    castObj := obj.(*apiextensionsv1.CustomResourceDefinition)
    // 只对已删除且具有指定Finalizer的对象进行排队。
    if !castObj.DeletionTimestamp.IsZero() && apiextensionshelpers.CRDHasFinalizer(castObj, apiextensionsv1.CustomResourceCleanupFinalizer) {
    	c.enqueue(castObj)
    }
}

// updateCustomResourceDefinition是一个事件处理函数，用于处理更新CustomResourceDefinition事件。
func (c *CRDFinalizer) updateCustomResourceDefinition(oldObj, newObj interface{}) {
    oldCRD := oldObj.(*apiextensionsv1.CustomResourceDefinition)
    newCRD := newObj.(*apiextensionsv1.CustomResourceDefinition)
    // 只对未删除且尚未由我们完成的对象进行排队。
    if newCRD.DeletionTimestamp.IsZero() || !apiextensionshelpers.CRDHasFinalizer(newCRD, apiextensionsv1.CustomResourceCleanupFinalizer) {
    	return
	}
    // 总是重新排队同步，以防万一
    if oldCRD.ResourceVersion == newCRD.ResourceVersion {
        c.enqueue(newCRD)
        return
    }

    // 如果唯一的区别在于终止条件，则没有必要在此重新排队。这个控制器可能是发起者，所以重新排队会热循环。失败将由工作队列直接重新排队。
    // 这是一个低流量和规模资源，所以复制是可怕的。这不好，因此欢迎更好的想法。
    oldCopy := oldCRD.DeepCopy()
    newCopy := newCRD.DeepCopy()
    oldCopy.ResourceVersion = ""
    newCopy.ResourceVersion = ""
    apiextensionshelpers.RemoveCRDCondition(oldCopy, apiextensionsv1.Terminating)
    apiextensionshelpers.RemoveCRDCondition(newCopy, apiextensionsv1.Terminating)

    if !reflect.DeepEqual(oldCopy, newCopy) {
        c.enqueue(newCRD)
    }
}

func (c *CRDFinalizer) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Info("Starting CRDFinalizer")
	defer klog.Info("Shutting down CRDFinalizer")

	if !cache.WaitForCacheSync(stopCh, c.crdSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	<-stopCh
}

// enqueue将CustomResourceDefinition对象加入队列。
func (c *CRDFinalizer) enqueue(obj *apiextensionsv1.CustomResourceDefinition) {
key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
    if err != nil {
        utilruntime.HandleError(fmt.Errorf("couldn't get key for object %#v: %v", obj, err))
        return
    }
    c.queue.Add(key)
}


func (c *CRDFinalizer) runWorker() {
	for c.processNextWorkItem() {
	}
}

// processNextWorkItem deals with one key off the queue.  It returns false when it's time to quit.
func (c *CRDFinalizer) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.syncFn(key.(string))
	if err == nil {
		c.queue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with: %v", key, err))
	c.queue.AddRateLimited(key)

	return true
}

func (c *CRDFinalizer) sync(key string) error {
	// sync方法用于同步自定义资源定义的状态，参数key表示要同步的资源定义的键

	cachedCRD, err := c.crdLister.Get(key)
	// 通过键获取自定义资源定义对象，并将结果赋值给cachedCRD
	if apierrors.IsNotFound(err) {
		// 如果资源定义不存在，则返回nil
		return nil
	}
	if err != nil {
		// 如果发生错误，则返回错误
		return err
	}

	// no work to do
	if cachedCRD.DeletionTimestamp.IsZero() || !apiextensionshelpers.CRDHasFinalizer(cachedCRD, apiextensionsv1.CustomResourceCleanupFinalizer) {
		// 如果自定义资源定义的DeletionTimestamp为零或不包含指定的Finalizer，则返回nil，无需进行操作
		return nil
	}

	crd := cachedCRD.DeepCopy()
	// 对自定义资源定义进行深拷贝，以避免修改原始对象

	// update the status condition.  This cleanup could take a while.
	// 更新状态条件。清理过程可能需要一些时间。
	apiextensionshelpers.SetCRDCondition(crd, apiextensionsv1.CustomResourceDefinitionCondition{
		Type:    apiextensionsv1.Terminating,
		Status:  apiextensionsv1.ConditionTrue,
		Reason:  "InstanceDeletionInProgress",
		Message: "CustomResource deletion is in progress",
	})
	crd, err = c.crdClient.CustomResourceDefinitions().UpdateStatus(context.TODO(), crd, metav1.UpdateOptions{})
	// 使用更新后的资源定义对象更新资源定义的状态
	if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		// 如果资源定义在更新过程中被删除或修改，则返回nil，稍后会再次调用sync方法进行同步
		return nil
	}
	if err != nil {
		// 如果发生其他错误，则返回错误
		return err
	}

	// Now we can start deleting items.  We should use the REST API to ensure that all normal admission runs.
	// Since we control the endpoints, we know that delete collection works. No need to delete if not established.
	// 现在我们可以开始删除项了。我们应该使用REST API来确保所有正常的审批运行。
	// 由于我们控制着终结点，我们知道删除集合是有效的。如果没有建立，就不需要删除。
	if OverlappingBuiltInResources()[schema.GroupResource{Group: crd.Spec.Group, Resource: crd.Spec.Names.Plural}] {
		// Skip deletion, explain why, and proceed to remove the finalizer and delete the CRD
		// 跳过删除操作，说明原因，然后继续删除最终器并删除CRD
		apiextensionshelpers.SetCRDCondition(crd, apiextensionsv1.CustomResourceDefinitionCondition{
			Type:    apiextensionsv1.Terminating,
			Status:  apiextensionsv1.ConditionFalse,
			Reason:  "OverlappingBuiltInResource",
			Message: "instances overlap with built-in resources in storage",
		})
	} else if apiextensionshelpers.IsCRDConditionTrue(crd, apiextensionsv1.Established) {
		// If the CRD is established, start deleting instances
		// 如果CRD已建立，则开始删除实例
		cond, deleteErr := c.deleteInstances(crd)
		// 调用deleteInstances方法删除实例，并获取返回的条件和错误
		apiextensionshelpers.SetCRDCondition(crd, cond)
		// 使用返回的条件更新CRD的条件
		if deleteErr != nil {
			// If there was an error during deletion, update the status and return the error
			// 如果删除过程中出现错误，则更新状态并返回错误
			if _, err = c.crdClient.CustomResourceDefinitions().UpdateStatus(context.TODO(), crd, metav1.UpdateOptions{}); err != nil {
				utilruntime.HandleError(err)
			}
			return deleteErr
		}
	} else {
		// If the CRD is not established, update the status condition accordingly
		// 如果CRD未建立，则相应地更新状态条件
		apiextensionshelpers.SetCRDCondition(crd, apiextensionsv1.CustomResourceDefinitionCondition{
			Type:    apiextensionsv1.Terminating,
			Status:  apiextensionsv1.ConditionFalse,
			Reason:  "NeverEstablished",
			Message: "resource was never established",
		})
	}

	apiextensionshelpers.CRDRemoveFinalizer(crd, apiextensionsv1.CustomResourceCleanupFinalizer)
	// 移除最终器
	_, err = c.crdClient.CustomResourceDefinitions().UpdateStatus(context.TODO(), crd, metav1.UpdateOptions{})
	// 使用更新后的CRD对象更新CRD的状态
	if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		// 如果CRD在更新过程中被删除或修改，则返回nil，稍后会再次调用sync方法进行同步
		return nil
	}
	return err
}

func (c *CRDFinalizer) deleteInstances(crd *apiextensionsv1.CustomResourceDefinition) (apiextensionsv1.CustomResourceDefinitionCondition, error) {
	// deleteInstances方法用于删除自定义资源的实例，参数crd表示要删除实例的自定义资源定义对象

	// Now we can start deleting items. While it would be ideal to use a REST API client, doing so
	// could incorrectly delete a ThirdPartyResource with the same URL as the CustomResource, so we go
	// directly to the storage instead. Since we control the storage, we know that delete collection works.
	// 现在我们可以开始删除项了。虽然使用REST API客户端是理想的，但这样做可能会错误地删除具有与CustomResource相同URL的ThirdPartyResource，因此我们直接访问存储。由于我们控制存储，我们知道删除集合是有效的。
	crClient, err := c.crClientGetter.GetCustomResourceListerCollectionDeleter(crd)
	// 通过CRD获取CustomResource的Lister、CollectionDeleter，并将结果赋值给crClient
	if err != nil {
		// 如果获取失败，则返回错误
		err = fmt.Errorf("unable to find a custom resource client for %s.%s: %v", crd.Status.AcceptedNames.Plural, crd.Spec.Group, err)
		return apiextensionsv1.CustomResourceDefinitionCondition{
			Type:    apiextensionsv1.Terminating,
			Status:  apiextensionsv1.ConditionTrue,
			Reason:  "InstanceDeletionFailed",
			Message: fmt.Sprintf("could not list instances: %v", err),
		}, err
	}

	ctx := genericapirequest.NewContext()
	allResources, err := crClient.List(ctx, nil)
	// 获取所有的CustomResource实例
	if err != nil {
		// 如果获取失败，则返回错误
		return apiextensionsv1.CustomResourceDefinitionCondition{
			Type:    apiextensionsv1.Terminating,
			Status:  apiextensionsv1.ConditionTrue,
			Reason:  "InstanceDeletionFailed",
			Message: fmt.Sprintf("could not list instances: %v", err),
		}, err
	}

	deletedNamespaces := sets.String{}
	deleteErrors := []error{}
	for _, item := range allResources.(*unstructured.UnstructuredList).Items {
		metadata, err := meta.Accessor(&item)
		// 获取CustomResource实例的元数据
		if err != nil {
			utilruntime.HandleError(err)
			continue
		}
		if deletedNamespaces.Has(metadata.GetNamespace()) {
			continue
		}
		// don't retry deleting the same namespace
		// 不要重试删除相同的命名空间
		deletedNamespaces.Insert(metadata.GetNamespace())
		nsCtx := genericapirequest.WithNamespace(ctx, metadata.GetNamespace())
		// 为命名空间创建上下文
		if _, err := crClient.DeleteCollection(nsCtx, rest.ValidateAllObjectFunc, nil, nil); err != nil {
			// 删除命名空间下的CustomResource实例集合
			deleteErrors = append(deleteErrors, err)
			continue
		}
	}
	if deleteError := utilerrors.NewAggregate(deleteErrors); deleteError != nil {
		// If there were errors during deletion, aggregate them and return the error
		// 如果删除过程中出现错误，则聚合这些错误并返回错误
		return apiextensionsv1.CustomResourceDefinitionCondition{
			Type:    apiextensionsv1.Terminating,
			Status:  apiextensionsv1.ConditionTrue,
			Reason:  "InstanceDeletionFailed",
			Message: fmt.Sprintf("could not issue all deletes: %v", deleteError),
		}, deleteError
	}

	// now we need to wait until all the resources are deleted.  Start with a simple poll before we do anything fancy.
	// TODO not all servers are synchronized on caches.  It is possible for a stale one to still be creating things.
	// Once we have a mechanism for servers to indicate their states, we should check that for concurrence.
	err = wait.PollImmediate(5*time.Second, 1*time.Minute, func() (bool, error) {
		listObj, err := crClient.List(ctx, nil)
		// 再次获取CustomResource实例列表
		if err != nil {
			return false, err
		}
		if len(listObj.(*unstructured.UnstructuredList).Items) == 0 {
			// If all instances are deleted, return true to exit the polling loop
			// 如果所有实例都被删除，则返回true以退出轮询循环
			return true, nil
		}
		klog.V(2).Infof("%s.%s waiting for %d items to be removed", crd.Status.AcceptedNames.Plural, crd.Spec.Group, len(listObj.(*unstructured.UnstructuredList).Items))
		return false, nil
	})
	if err != nil {
		// If the deletion check fails, update the status and return the error
		// 如果删除检查失败，则更新状态并返回错误
		return apiextensionsv1.CustomResourceDefinitionCondition{
			Type:    apiextensionsv1.Terminating,
			Status:  apiextensionsv1.ConditionTrue,
			Reason:  "InstanceDeletionCheckFailed",
			Message: fmt.Sprintf("failed to delete instances: %v", err),
		}, err
	}

	return apiextensionsv1.CustomResourceDefinitionCondition{
		Type:   apiextensionsv1.Terminating,
		Status: apiextensionsv1.ConditionFalse,
	}, nil
}
```

#### openapicontroller.NewController

该Controller的作用是监视CustomResourceDefinitions（CRD）并发布验证模式

1. 监听CRD事件：该Controller注册为CRD的事件处理程序，监听CRD的添加、更新和删除事件。
2. 处理CRD添加事件：当检测到添加了一个新的CRD时，该Controller会将该CRD对象添加到队列中，以便后续处理。
3. 处理CRD更新事件：当检测到CRD发生更新时，该Controller会将更新后的CRD对象添加到队列中，以便后续处理。
4. 处理CRD删除事件：当检测到CRD被删除时，该Controller会将被删除的CRD对象添加到队列中，以便后续处理。
5. 将CRD对象加入队列：该Controller使用队列来管理待处理的CRD对象。它将CRD对象的名称添加到队列中。
6. 发布验证模式：该Controller负责根据CRD定义的规范生成验证模式（Swagger），并将其发布供其他组件使用。

```GO
// Controller用于监视CustomResourceDefinitions（CRD）并发布验证模式。
type Controller struct {
    crdLister listers.CustomResourceDefinitionLister
    crdsSynced cache.InformerSynced
    // 为了测试目的，允许注入syncFn函数。
    syncFn func(string) error

    queue workqueue.RateLimitingInterface

    staticSpec     *spec.Swagger
    openAPIService *handler.OpenAPIService

    // 按版本和CRD名称存储的规范
    lock     sync.Mutex
    crdSpecs map[string]map[string]*spec.Swagger
}

// NewController使用输入的CustomResourceDefinition informer创建一个新的Controller。
func NewController(crdInformer informers.CustomResourceDefinitionInformer) *Controller {
    c := &Controller{
        crdLister: crdInformer.Lister(),
        crdsSynced: crdInformer.Informer().HasSynced,
        queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "crd_openapi_controller"),
        crdSpecs: map[string]map[string]*spec.Swagger{},
    }

    crdInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc:    c.addCustomResourceDefinition,
        UpdateFunc: c.updateCustomResourceDefinition,
        DeleteFunc: c.deleteCustomResourceDefinition,
    })

    c.syncFn = c.sync
    return c
}

// addCustomResourceDefinition是一个事件处理函数，用于处理添加CustomResourceDefinition事件。
func (c *Controller) addCustomResourceDefinition(obj interface{}) {
    castObj := obj.(*apiextensionsv1.CustomResourceDefinition)
    klog.V(4).Infof("添加customresourcedefinition %s", castObj.Name)
    c.enqueue(castObj)
}

// updateCustomResourceDefinition是一个事件处理函数，用于处理更新CustomResourceDefinition事件。
func (c *Controller) updateCustomResourceDefinition(oldObj, newObj interface{}) {
    castNewObj := newObj.(*apiextensionsv1.CustomResourceDefinition)
    klog.V(4).Infof("更新customresourcedefinition %s", castNewObj.Name)
    c.enqueue(castNewObj)
}

// deleteCustomResourceDefinition是一个事件处理函数，用于处理删除CustomResourceDefinition事件。
func (c *Controller) deleteCustomResourceDefinition(obj interface{}) {
    castObj, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
    if !ok {
        tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
        if !ok {
            klog.Errorf("无法从tombstone中获取对象 %#v", obj)
            return
        }
        castObj, ok = tombstone.Obj.(*apiextensionsv1.CustomResourceDefinition)
        if !ok {
            klog.Errorf("tombstone包含了意外的对象 %#v", obj)
            return
        }
    }
    klog.V(4).Infof("删除customresourcedefinition %q", castObj.Name)
    c.enqueue(castObj)
}

// enqueue将CustomResourceDefinition对象加入队列。
func (c *Controller) enqueue(obj *apiextensionsv1.CustomResourceDefinition) {
	c.queue.Add(obj.Name)
}

// Run函数设置openAPIAggregationManager并启动工作线程。

func (c *Controller) Run(staticSpec *spec.Swagger, openAPIService *handler.OpenAPIService, stopCh <-chan struct{}) {
    defer utilruntime.HandleCrash()
    defer c.queue.ShutDown()
    defer klog.Infof("关闭OpenAPI控制器")
	klog.Infof("启动OpenAPI控制器")

    c.staticSpec = staticSpec
    c.openAPIService = openAPIService

    // 等待缓存同步完成
    if !cache.WaitForCacheSync(stopCh, c.crdsSynced) {
        utilruntime.HandleError(fmt.Errorf("等待缓存同步超时"))
        return
    }

    // 创建初始规范以避免启动时每个CRD合并一次
    crds, err := c.crdLister.List(labels.Everything())
    if err != nil {
        utilruntime.HandleError(fmt.Errorf("无法初始化列出所有CRD：%v", err))
        return
    }
    for _, crd := range crds {
        if !apiextensionshelpers.IsCRDConditionTrue(crd, apiextensionsv1.Established) {
            continue
        }
        newSpecs, changed, err := buildVersionSpecs(crd, nil)
        if err != nil {
            utilruntime.HandleError(fmt.Errorf("无法构建CRD %s的OpenAPI规范：%v", crd.Name, err))
        } else if !changed {
            continue
        }
        c.crdSpecs[crd.Name] = newSpecs
    }
    if err := c.updateSpecLocked(); err != nil {
        utilruntime.HandleError(fmt.Errorf("无法初始化创建CRD的OpenAPI规范：%v", err))
        return
    }

    // 只启动一个工作线程，因为这是一个缓慢运行的API
    go wait.Until(c.runWorker, time.Second, stopCh)

    <-stopCh
}
    
func (c *Controller) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	// log slow aggregations
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		if elapsed > time.Second {
			klog.Warningf("slow openapi aggregation of %q: %s", key.(string), elapsed)
		}
	}()

	err := c.syncFn(key.(string))
	if err == nil {
		c.queue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with: %v", key, err))
	c.queue.AddRateLimited(key)
	return true
}

func (c *Controller) sync(name string) error {
	c.lock.Lock() // 加锁
	defer c.lock.Unlock() // 解锁

	crd, err := c.crdLister.Get(name) // 获取指定名称的 CRD
	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	// do we have to remove all specs of this CRD?
	if errors.IsNotFound(err) || !apiextensionshelpers.IsCRDConditionTrue(crd, apiextensionsv1.Established) {
		// 需要删除该 CRD 的所有规范吗？
		if _, found := c.crdSpecs[name]; !found {
			return nil
		}
		delete(c.crdSpecs, name) // 从 crdSpecs 中删除指定名称的 CRD
		klog.V(2).Infof("Updating CRD OpenAPI spec because %s was removed", name) // 记录日志，更新 CRD 的 OpenAPI 规范，因为 CRD 被移除了
		regenerationCounter.With(map[string]string{"crd": name, "reason": "remove"}) // 记录计数器
		return c.updateSpecLocked() // 更新规范
	}

	// compute CRD spec and see whether it changed
	oldSpecs, updated := c.crdSpecs[crd.Name] // 获取指定名称的 CRD 的旧规范
	newSpecs, changed, err := buildVersionSpecs(crd, oldSpecs) // 构建指定名称的 CRD 的新规范，并判断规范是否发生变化
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}

	// update specs of this CRD
	c.crdSpecs[crd.Name] = newSpecs // 更新指定名称的 CRD 的规范
	klog.V(2).Infof("Updating CRD OpenAPI spec because %s changed", name) // 记录日志，更新 CRD 的 OpenAPI 规范，因为 CRD 发生了变化
	reason := "add"
	if updated {
		reason = "update"
	}
	regenerationCounter.With(map[string]string{"crd": name, "reason": reason}) // 记录计数器
	return c.updateSpecLocked() // 更新规范
}

func buildVersionSpecs(crd *apiextensionsv1.CustomResourceDefinition, oldSpecs map[string]*spec.Swagger) (map[string]*spec.Swagger, bool, error) {
	newSpecs := map[string]*spec.Swagger{}
	anyChanged := false
	for _, v := range crd.Spec.Versions {
		if !v.Served {
			continue
		}
		spec, err := builder.BuildOpenAPIV2(crd, v.Name, builder.Options{V2: true}) // 构建指定 CRD 版本的 OpenAPI 规范
		// Defaults must be pruned here for CRDs to cleanly merge with the static
		// spec that already has defaults pruned
		spec.Definitions = handler.PruneDefaults(spec.Definitions) // 删除规范中的默认值
		if err != nil {
			return nil, false, err
		}
		newSpecs[v.Name] = spec // 将构建得到的规范存入 newSpecs 中
		if oldSpecs[v.Name] == nil || !reflect.DeepEqual(oldSpecs[v.Name], spec) {
			anyChanged = true // 标记规范是否发生变化
		}
	}
	if !anyChanged && len(oldSpecs) == len(newSpecs) {
		return newSpecs, false, nil
	}

	return newSpecs, true, nil
}

// updateSpecLocked aggregates all OpenAPI specs and updates openAPIService.
// It is not thread-safe. The caller is responsible to hold proper lock (Controller.lock).
func (c *Controller) updateSpecLocked() error {
	crdSpecs := []*spec.Swagger{}
	for _, versionSpecs := range c.crdSpecs {
		for _, s := range versionSpecs {
			crdSpecs = append(crdSpecs, s) // 将所有的 OpenAPI 规范聚合到 crdSpecs 中
		}
	}
	mergedSpec, err := builder.MergeSpecs(c.staticSpec, crdSpecs...) // 将静态规范和 CRD 规范合并成一个规范
	if err != nil {
		return fmt.Errorf("failed to merge specs: %v", err)
	}
	return c.openAPIService.UpdateSpec(mergedSpec) // 更新 openAPIService 的规范
}
```

#### openapiv3controller.NewController

这个 `Controller` 的作用是监视 `CustomResourceDefinitions`（自定义资源定义）并发布 `OpenAPI v3`。它是一个控制器（Controller），用于处理与自定义资源定义相关的操作和事件。

1. 监听 `CustomResourceDefinitions` 的变化，包括添加、更新和删除操作。
2. 通过调用相应的方法将变化后的 `CustomResourceDefinition` 对象添加到工作队列中。
3. 通过工作队列，控制并限制处理变化后的 `CustomResourceDefinition` 对象的速率。
4. 提供同步函数 `syncFn`，用于处理自定义资源定义的同步操作。
5. 维护 `OpenAPI v3` 规范（`specsByGVandName`）的版本和资源名称的映射关系。

```go
// Controller 监听 CustomResourceDefinitions 并发布 OpenAPI v3
type Controller struct {
    crdLister listers.CustomResourceDefinitionLister
    crdsSynced cache.InformerSynced
    syncFn func(string) error
    queue workqueue.RateLimitingInterface
    openAPIV3Service *handler3.OpenAPIService
    lock sync.Mutex
    specsByGVandName map[schema.GroupVersion]map[string]*spec3.OpenAPI
}

// NewController 使用给定的 CustomResourceDefinition informer 创建一个新的 Controller
func NewController(crdInformer informers.CustomResourceDefinitionInformer) *Controller {
    c := &Controller{
        crdLister: crdInformer.Lister(),
        crdsSynced: crdInformer.Informer().HasSynced,
        queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "crd_openapi_v3_controller"),
        specsByGVandName: map[schema.GroupVersion]map[string]*spec3.OpenAPI{},
    }

    crdInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc:    c.addCustomResourceDefinition,
        UpdateFunc: c.updateCustomResourceDefinition,
        DeleteFunc: c.deleteCustomResourceDefinition,
    })

    c.syncFn = c.sync
    return c
}

// addCustomResourceDefinition 是 Controller 的方法，用于添加 CustomResourceDefinition
func (c *Controller) addCustomResourceDefinition(obj interface{}) {
castObj := obj.(*apiextensionsv1.CustomResourceDefinition)
klog.V(4).Infof("正在添加 customresourcedefinition %s", castObj.Name)
c.enqueue(castObj)
}

// updateCustomResourceDefinition 是 Controller 的方法，用于更新 CustomResourceDefinition
func (c *Controller) updateCustomResourceDefinition(oldObj, newObj interface{}) {
    castNewObj := newObj.(*apiextensionsv1.CustomResourceDefinition)
    klog.V(4).Infof("正在更新 customresourcedefinition %s", castNewObj.Name)
    c.enqueue(castNewObj)
}

// deleteCustomResourceDefinition 是 Controller 的方法，用于删除 CustomResourceDefinition
func (c *Controller) deleteCustomResourceDefinition(obj interface{}) {
castObj, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
    if !ok {
        tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
        if !ok {
            klog.Errorf("无法从 tombstone 获取对象 %#v", obj)
            return
        }
        castObj, ok = tombstone.Obj.(*apiextensionsv1.CustomResourceDefinition)
        if !ok {
            klog.Errorf("Tombstone 包含了意外的对象 %#v", obj)
            return
        }
    }
    klog.V(4).Infof("正在删除 customresourcedefinition %q", castObj.Name)
    c.enqueue(castObj)
}

// enqueue 是 Controller 的方法，用于将 CustomResourceDefinition 加入队列
func (c *Controller) enqueue(obj *apiextensionsv1.CustomResourceDefinition) {
	c.queue.Add(obj.Name)
}

// Run sets openAPIAggregationManager and starts workers
func (c *Controller) Run(openAPIV3Service *handler3.OpenAPIService, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()
	defer klog.Infof("Shutting down OpenAPI V3 controller")

	klog.Infof("Starting OpenAPI V3 controller")

	c.openAPIV3Service = openAPIV3Service

	if !cache.WaitForCacheSync(stopCh, c.crdsSynced) {
		utilruntime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}

	crds, err := c.crdLister.List(labels.Everything())
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("failed to initially list all CRDs: %v", err))
		return
	}
	for _, crd := range crds {
		if !apiextensionshelpers.IsCRDConditionTrue(crd, apiextensionsv1.Established) {
			continue
		}
		for _, v := range crd.Spec.Versions {
			if !v.Served {
				continue
			}
			c.buildV3Spec(crd, crd.Name, v.Name)
		}
	}

	// only start one worker thread since its a slow moving API
	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
}

func (c *Controller) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	// log slow aggregations
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		if elapsed > time.Second {
			klog.Warningf("slow openapi aggregation of %q: %s", key.(string), elapsed)
		}
	}()

	err := c.syncFn(key.(string))
	if err == nil {
		c.queue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with: %v", key, err))
	c.queue.AddRateLimited(key)
	return true
}

func (c *Controller) sync(name string) error {
	c.lock.Lock() // 加锁
	defer c.lock.Unlock() // 解锁

	crd, err := c.crdLister.Get(name) // 获取指定名称的 CRD
	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	if errors.IsNotFound(err) || !apiextensionshelpers.IsCRDConditionTrue(crd, apiextensionsv1.Established) {
		c.deleteCRD(name) // 删除指定名称的 CRD
		return nil
	}

	for _, v := range crd.Spec.Versions {
		if !v.Served {
			continue
		}
		c.buildV3Spec(crd, name, v.Name) // 构建指定名称的 CRD 的指定版本的 V3 规范
	}

	return nil
}

func (c *Controller) deleteCRD(name string) {
	for gv, crdListForGV := range c.specsByGVandName {
		_, needOpenAPIUpdate := crdListForGV[name]
		if needOpenAPIUpdate {
			delete(crdListForGV, name) // 从 specsByGVandName 中删除指定名称的 CRD
			if len(crdListForGV) == 0 {
				delete(c.specsByGVandName, gv) // 如果该组版本下没有其他 CRD，则从 specsByGVandName 中删除该组版本
			}
			regenerationCounter.With(map[string]string{"group": gv.Group, "version": gv.Version, "crd": name, "reason": "remove"}) // 记录计数器
			c.updateGroupVersion(gv) // 更新组版本
		}
	}
}

func (c *Controller) updateGroupVersion(gv schema.GroupVersion) error {
	if _, ok := c.specsByGVandName[gv]; !ok {
		c.openAPIV3Service.DeleteGroupVersion(groupVersionToOpenAPIV3Path(gv)) // 删除指定组版本的 OpenAPI V3 规范
		return nil
	}

	var specs []*spec3.OpenAPI
	for _, spec := range c.specsByGVandName[gv] {
		specs = append(specs, spec) // 将该组版本下的所有规范加入 specs 数组
	}

	mergedSpec, err := builder.MergeSpecsV3(specs...) // 将所有规范合并成一个规范
	if err != nil {
		return fmt.Errorf("failed to merge specs: %v", err)
	}

	c.openAPIV3Service.UpdateGroupVersion(groupVersionToOpenAPIV3Path(gv), mergedSpec) // 更新指定组版本的 OpenAPI V3 规范
	return nil
}

func (c *Controller) updateCRDSpec(crd *apiextensionsv1.CustomResourceDefinition, name, versionName string, v3 *spec3.OpenAPI) error {
	gv := schema.GroupVersion{
		Group:   crd.Spec.Group,
		Version: versionName,
	}

	_, ok := c.specsByGVandName[gv]
	reason := "update"
	if !ok {
		reason = "add"
		c.specsByGVandName[gv] = map[string]*spec3.OpenAPI{}
	}

	oldSpec, ok := c.specsByGVandName[gv][name]
	if ok {
		if reflect.DeepEqual(oldSpec, v3) {
			// no changes to CRD
			return nil
			// 如果 CRD 没有发生变化，直接返回
		}
	}
	c.specsByGVandName[gv][name] = v3 // 更新 CRD 的规范
	regenerationCounter.With(map[string]string{"crd": name, "group": gv.Group, "version": gv.Version, "reason": reason}) // 记录计数器
	return c.updateGroupVersion(gv) // 更新组版本
}

func (c *Controller) buildV3Spec(crd *apiextensionsv1.CustomResourceDefinition, name, versionName string) error {
	v3, err := builder.BuildOpenAPIV3(crd, versionName, builder.Options{V2: false}) // 构建指定版本的 CRD 的 V3 规范
	if err != nil {
		return err
	}

	c.updateCRDSpec(crd, name, versionName, v3) // 更新 CRD 的规范
	return nil
}
```

