---
title: "kube-apiserver Handlerchain 代码走读"
subtitle:
date: 2023-05-23T21:45:06+08:00
draft: false
toc: true
categories: [cloud]
tags: [kubernetes]
authors:
    - haiyux
#featuredImagePreview: /img/preview/apiserver/kube-apiserver-createserverchain.jpg
---

## Handlerchain做什么的？

在请求处理过程中，存在一种类似于中间件的机制，它在主逻辑之前执行。这种机制可以被看作是在请求处理中的一个环节。

因为`handler.ServeHTTP`都是在最后执行的（除非遇到特殊情况）。所以每个handlerFunc执行顺序是返回来的。

```GO
package main

import (
	"fmt"
	"net/http"
)

func main() {
	handler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello")
	}
	handler = func(handler http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "middleware1")
			handler.ServeHTTP(w, r)
		}
	}(handler)
	handler = func(handler http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "middleware2")
			handler.ServeHTTP(w, r)
		}
	}(handler)
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}

/*
curl http://127.0.0.1:8080/
middleware2
middleware1
hello
*/
```

## DefaultBuildHandlerChain

```GO
func DefaultBuildHandlerChain(apiHandler http.Handler, c *Config) http.Handler {
	// 通过 filterlatency 包中的 TrackCompleted 函数对 apiHandler 进行追踪
	handler := filterlatency.TrackCompleted(apiHandler)

	// 使用 genericapifilters 包中的 WithAuthorization 函数添加授权过滤器
	handler = genericapifilters.WithAuthorization(handler, c.Authorization.Authorizer, c.Serializer)

	// 使用 filterlatency 包中的 TrackStarted 函数对 handler 进行追踪，并设置名称为 "authorization"
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "authorization")

	// 如果存在流量控制
	if c.FlowControl != nil {
		// 创建默认的流量估算器配置
		workEstimatorCfg := flowcontrolrequest.DefaultWorkEstimatorConfig()

		// 创建流量估算器，并使用 c.StorageObjectCountTracker.Get 和 c.FlowControl.GetInterestedWatchCount 函数作为参数
		requestWorkEstimator := flowcontrolrequest.NewWorkEstimator(
			c.StorageObjectCountTracker.Get, c.FlowControl.GetInterestedWatchCount, workEstimatorCfg)

		// 使用 filterlatency 包中的 TrackCompleted 函数对 handler 进行追踪
		handler = filterlatency.TrackCompleted(handler)

		// 使用 genericfilters 包中的 WithPriorityAndFairness 函数添加优先级和公平性过滤器
		handler = genericfilters.WithPriorityAndFairness(handler, c.LongRunningFunc, c.FlowControl, requestWorkEstimator)

		// 使用 filterlatency 包中的 TrackStarted 函数对 handler 进行追踪，并设置名称为 "priorityandfairness"
		handler = filterlatency.TrackStarted(handler, c.TracerProvider, "priorityandfairness")
	} else {
		// 使用 genericfilters 包中的 WithMaxInFlightLimit 函数添加最大并发限制过滤器
		handler = genericfilters.WithMaxInFlightLimit(handler, c.MaxRequestsInFlight, c.MaxMutatingRequestsInFlight, c.LongRunningFunc)
	}

	// 使用 filterlatency 包中的 TrackCompleted 函数对 handler 进行追踪
	handler = filterlatency.TrackCompleted(handler)

	// 使用 genericapifilters 包中的 WithImpersonation 函数添加模拟身份过滤器
	handler = genericapifilters.WithImpersonation(handler, c.Authorization.Authorizer, c.Serializer)

	// 使用 filterlatency 包中的 TrackStarted 函数对 handler 进行追踪，并设置名称为 "impersonation"
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "impersonation")

	// 使用 filterlatency 包中的 TrackCompleted 函数对 handler 进行追踪
	handler = filterlatency.TrackCompleted(handler)

	// 使用 genericapifilters 包中的 WithAudit 函数添加审计过滤器
	handler = genericapifilters.WithAudit(handler, c.AuditBackend, c.AuditPolicyRuleEvaluator, c.LongRunningFunc)

	// 使用 filterlatency 包中的 TrackStarted 函数对 handler 进行追踪，并设置名称为 "audit"
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "audit")

	// 创建失败处理器，并使用 genericapifilters 包中的 Unauthorized 函数初始化
	failedHandler := genericapifilters.Unauthorized(c.Serializer)

	// 使用 genericapifilters 包中的 WithFailedAuthenticationAudit 函数添加失败身份验证审计过滤器
	failedHandler = genericapifilters.WithFailedAuthenticationAudit(failedHandler, c.AuditBackend, c.AuditPolicyRuleEvaluator)

	// 使用 filterlatency 包中的 TrackCompleted 函数对 failedHandler 进行追踪
	failedHandler = filterlatency.TrackCompleted(failedHandler)

	// 使用 filterlatency 包中的 TrackCompleted 函数对 handler 进行追踪
	handler = filterlatency.TrackCompleted(handler)

	// 使用 genericapifilters 包中的 WithAuthentication 函数添加身份验证过滤器
	handler = genericapifilters.WithAuthentication(handler, c.Authentication.Authenticator, failedHandler, c.Authentication.APIAudiences, c.Authentication.RequestHeaderConfig)

	// 使用 filterlatency 包中的 TrackStarted 函数对 handler 进行追踪，并设置名称为 "authentication"
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "authentication")

	// 使用 genericfilters 包中的 WithCORS 函数添加跨域资源共享过滤器
	handler = genericfilters.WithCORS(handler, c.CorsAllowedOriginList, nil, nil, nil, "true")

	// 使用 genericfilters 包中的 WithTimeoutForNonLongRunningRequests 函数为非长时间运行的请求设置超时处理
	handler = genericfilters.WithTimeoutForNonLongRunningRequests(handler, c.LongRunningFunc)

	// 使用 genericapifilters 包中的 WithRequestDeadline 函数为请求设置截止时间
	handler = genericapifilters.WithRequestDeadline(handler, c.AuditBackend, c.AuditPolicyRuleEvaluator,
		c.LongRunningFunc, c.Serializer, c.RequestTimeout)

	// 使用 genericfilters 包中的 WithWaitGroup 函数添加等待组过滤器
	handler = genericfilters.WithWaitGroup(handler, c.LongRunningFunc, c.NonLongRunningRequestWaitGroup)

	// 如果存在关闭观察终止优雅期
	if c.ShutdownWatchTerminationGracePeriod > 0 {
		// 使用 genericfilters 包中的 WithWatchTerminationDuringShutdown 函数添加关闭观察期间终止过滤器
		handler = genericfilters.WithWatchTerminationDuringShutdown(handler, c.lifecycleSignals, c.WatchRequestWaitGroup)
	}

	// 如果存在 SecureServing，并且不禁用 HTTP/2，并且 GoawayChance 大于 0
	if c.SecureServing != nil && !c.SecureServing.DisableHTTP2 && c.GoawayChance > 0 {
		// 使用 genericfilters 包中的 WithProbabilisticGoaway 函数添加概率性 Goaway 过滤器
		handler = genericfilters.WithProbabilisticGoaway(handler, c.GoawayChance)
	}

	// 使用 genericapifilters 包中的 WithWarningRecorder 函数添加警告记录过滤器
	handler = genericapifilters.WithWarningRecorder(handler)

	// 使用 genericapifilters 包中的 WithCacheControl 函数添加缓存控制过滤器
	handler = genericapifilters.WithCacheControl(handler)

	// 使用 genericfilters 包中的 WithHSTS 函数添加 HTTP 严格传输安全（HSTS）过滤器
	handler = genericfilters.WithHSTS(handler, c.HSTSDirectives)

	// 如果 ShutdownSendRetryAfter 为 true
	if c.ShutdownSendRetryAfter {
		// 使用 genericfilters 包中的 WithRetryAfter 函数添加重试后过滤器
		handler = genericfilters.WithRetryAfter(handler, c.lifecycleSignals.NotAcceptingNewRequest.Signaled())
	}

	// 使用 genericfilters 包中的 WithHTTPLogging 函数添加 HTTP 日志记录过滤器
	handler = genericfilters.WithHTTPLogging(handler)

	// 如果 genericfeatures 包中的 APIServerTracing 特性启用
	if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.APIServerTracing) {
		// 使用 genericapifilters 包中的 WithTracing 函数添加追踪过滤器
		handler = genericapifilters.WithTracing(handler, c.TracerProvider)
	}

	// 使用 genericapifilters 包中的 WithLatencyTrackers 函数添加延迟追踪过滤器
	handler = genericapifilters.WithLatencyTrackers(handler)

	// 使用 genericapifilters 包中的 WithRequestInfo 函数添加请求信息过滤器
	handler = genericapifilters.WithRequestInfo(handler, c.RequestInfoResolver)

	// 使用 genericapifilters 包中的 WithRequestReceivedTimestamp 函数添加请求接收时间戳过滤器
	handler = genericapifilters.WithRequestReceivedTimestamp(handler)

	// 使用 genericapifilters 包中的 WithMuxAndDiscoveryComplete 函数添加多路复用和发现完成过滤器
	handler = genericapifilters.WithMuxAndDiscoveryComplete(handler, c.lifecycleSignals.MuxAndDiscoveryComplete.Signaled())

	// 使用 genericfilters 包中的 WithPanicRecovery 函数添加恢复 panic 过滤器
	handler = genericfilters.WithPanicRecovery(handler, c.RequestInfoResolver)

	// 使用 genericapifilters 包中的 WithAuditInit 函数初始化审计过滤器
	handler = genericapifilters.WithAuditInit(handler)

	return handler
}
```

## TrackCompleted&TrackStarted

metrics

```GO
// TrackCompleted 测量给定处理程序执行完成的时间戳，然后使用过滤器延迟持续时间更新相应的指标。
func TrackCompleted(handler http.Handler) http.Handler {
	// 调用 trackCompleted 函数，传入处理程序、RealClock 实例和回调函数
	return trackCompleted(handler, clock.RealClock{}, func(ctx context.Context, fr *requestFilterRecord, completedAt time.Time) {
		// 计算延迟时间
		latency := completedAt.Sub(fr.startedTimestamp)
		// 使用 metrics 包中的 RecordFilterLatency 函数记录过滤器延迟
		metrics.RecordFilterLatency(ctx, fr.name, latency)
		// 如果启用了日志级别为 3 并且延迟超过最小过滤器日志延迟时间
		if klog.V(3).Enabled() && latency > minFilterLatencyToLog {
			// 使用 httplog 包中的 AddKeyValue 函数将延迟时间添加到日志上下文中
			httplog.AddKeyValue(ctx, fmt.Sprintf("fl_%s", fr.name), latency.String())
		}
	})
}

// RecordFilterLatency 记录过滤器延迟的函数
func RecordFilterLatency(ctx context.Context, name string, elapsed time.Duration) {
	// 使用 requestFilterDuration 计时器指标记录上下文和标签值的过滤器延迟观察值
	requestFilterDuration.WithContext(ctx).WithLabelValues(name).Observe(elapsed.Seconds())
}
```

```GO
// TrackStarted 测量给定处理程序开始执行的时间戳，通过将处理程序附加到处理链中。
func TrackStarted(handler http.Handler, tp trace.TracerProvider, name string) http.Handler {
	// 调用 trackStarted 函数，传入处理程序、追踪器提供程序、名称和 RealClock 实例
	return trackStarted(handler, tp, name, clock.RealClock{})
}

func trackStarted(handler http.Handler, tp trace.TracerProvider, name string, clock clock.PassiveClock) http.Handler {
	// 如果追踪功能被禁用，NoopTracerProvider 将用于 tp，此时该函数不会进行任何操作
	tracer := tp.Tracer("k8s.op/apiserver/pkg/endpoints/filterlatency")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// 从上下文中获取请求过滤器记录
		if fr := requestFilterRecordFrom(ctx); fr != nil {
			fr.name = name
			fr.startedTimestamp = clock.Now()

			// 调用处理程序处理请求
			handler.ServeHTTP(w, r)
			return
		}

		// 创建新的请求过滤器记录
		fr := &requestFilterRecord{
			name:             name,
			startedTimestamp: clock.Now(),
		}
		// 使用追踪器开始追踪，并更新上下文和请求对象
		ctx, _ = tracer.Start(ctx, name)
		r = r.WithContext(withRequestFilterRecord(ctx, fr))
		// 调用处理程序处理请求
		handler.ServeHTTP(w, r)
	})
}
```

### requestFilterRecord

```GO
// requestFilterRecord 是请求过滤器记录的结构体类型
type requestFilterRecord struct {
	name             string        // 过滤器名称
	startedTimestamp time.Time     // 过滤器开始时间戳
}
```

## WithAuthorization

用于验证账号授权

```GO
// WithAuthorization 将所有经过授权的请求传递给处理程序，否则返回禁止访问的错误。
func WithAuthorization(handler http.Handler, auth authorizer.Authorizer, s runtime.NegotiatedSerializer) http.Handler {
	// 调用 withAuthorization 函数，传入处理程序、授权器、序列化器和记录授权指标的函数
	return withAuthorization(handler, auth, s, recordAuthorizationMetrics)
}

func withAuthorization(handler http.Handler, a authorizer.Authorizer, s runtime.NegotiatedSerializer, metrics recordAuthorizationMetricsFunc) http.Handler {
	if a == nil {
		klog.Warning("Authorization is disabled")  // 授权功能被禁用的警告日志
		return handler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		authorizationStart := time.Now()  // 授权开始时间

		attributes, err := GetAuthorizerAttributes(ctx)  // 获取授权器属性
		if err != nil {
			responsewriters.InternalError(w, req, err)
			return
		}
		authorized, reason, err := a.Authorize(ctx, attributes)  // 授权判断

		authorizationFinish := time.Now()  // 授权结束时间
		defer func() {
			metrics(ctx, authorized, err, authorizationStart, authorizationFinish)  // 记录授权指标
		}()

		// 如果授权决策为允许
		if authorized == authorizer.DecisionAllow {
			audit.AddAuditAnnotations(ctx,
				decisionAnnotationKey, decisionAllow,
				reasonAnnotationKey, reason)
			handler.ServeHTTP(w, req)  // 调用处理程序处理请求
			return
		}
		// 如果发生错误
		if err != nil {
			audit.AddAuditAnnotation(ctx, reasonAnnotationKey, reasonError)
			responsewriters.InternalError(w, req, err)
			return
		}

		klog.V(4).InfoS("Forbidden", "URI", req.RequestURI, "reason", reason)  // 输出禁止访问的日志
		audit.AddAuditAnnotations(ctx,
			decisionAnnotationKey, decisionForbid,
			reasonAnnotationKey, reason)
		responsewriters.Forbidden(ctx, attributes, w, req, reason, s)  // 返回禁止访问的响应
	})
}

func GetAuthorizerAttributes(ctx context.Context) (authorizer.Attributes, error) {
	attribs := authorizer.AttributesRecord{}

	user, ok := request.UserFrom(ctx)
	if ok {
		attribs.User = user
	}

	requestInfo, found := request.RequestInfoFrom(ctx)
	if !found {
		return nil, errors.New("no RequestInfo found in the context")
	}

	// 开始设置适用于资源和非资源请求的通用属性
	attribs.ResourceRequest = requestInfo.IsResourceRequest
	attribs.Path = requestInfo.Path
	attribs.Verb = requestInfo.Verb

	attribs.APIGroup = requestInfo.APIGroup
	attribs.APIVersion = requestInfo.APIVersion
	attribs.Resource = requestInfo.Resource
	attribs.Subresource = requestInfo.Subresource
	attribs.Namespace = requestInfo.Namespace
	attribs.Name = requestInfo.Name

	return &attribs, nil
}

type Authorizer interface {
	Authorize(ctx context.Context, a Attributes) (authorized Decision, reason string, err error)
}
```

## WithPriorityAndFairness

用于处理请求的优先级和公平性。

```GO
// WithPriorityAndFairness函数用于实现在细粒度上限制并发请求的数量。
// 参数:
// - handler: http.Handler类型，表示原始的请求处理程序。
// - longRunningRequestCheck: apirequest.LongRunningRequestCheck类型，用于检查是否为长时间运行的请求。
// - fcIfc: utilflowcontrol.Interface类型，表示流量控制的接口。
// - workEstimator: flowcontrolrequest.WorkEstimatorFunc类型，表示工作量估算函数。
func WithPriorityAndFairness(
    handler http.Handler,
    longRunningRequestCheck apirequest.LongRunningRequestCheck,
    fcIfc utilflowcontrol.Interface,
    workEstimator flowcontrolrequest.WorkEstimatorFunc,
) http.Handler {
    // 如果流量控制接口为空，则记录警告日志并返回原始的请求处理程序。
    if fcIfc == nil {
        klog.Warningf("priority and fairness support not found, skipping")
        return handler
	}
    // 初始化一次最大并发请求数量。
    initAPFOnce.Do(func() {
        initMaxInFlight(0, 0)

        // 延迟获取这些度量标，直到它们的基础度量已注册，
        // 以便与高效的实现关联起来。
        waitingMark.readOnlyObserver = fcmetrics.GetWaitingReadonlyConcurrency()
        waitingMark.mutatingObserver = fcmetrics.GetWaitingMutatingConcurrency()
    })

    // 创建priorityAndFairnessHandler实例。
    priorityAndFairnessHandler := &priorityAndFairnessHandler{
        handler:                 handler,
        longRunningRequestCheck: longRunningRequestCheck,
        fcIfc:                   fcIfc,
        workEstimator:           workEstimator,
        droppedRequests:         utilflowcontrol.NewDroppedRequestsTracker(),
    }

    // 返回一个http.Handler类型的处理程序，该处理程序调用priorityAndFairnessHandler的Handle方法。
    return http.HandlerFunc(priorityAndFairnessHandler.Handle)
}
```

### initMaxInFlight

```GO
// initMaxInFlightOnce是用于保证initMaxInFlight函数只执行一次的同步标志。
var initMaxInFlightOnce sync.Once

// initMaxInFlight函数用于初始化最大并发请求数量。
func initMaxInFlight(nonMutatingLimit, mutatingLimit int) {
    // 保证initMaxInFlight函数只执行一次。
    initMaxInFlightOnce.Do(func() {
        // 延迟获取这些度量标，直到它们的基础度量已注册，
        // 以便与高效的实现关联起来。
        watermark.readOnlyObserver = fcmetrics.GetExecutingReadonlyConcurrency()
        watermark.mutatingObserver = fcmetrics.GetExecutingMutatingConcurrency()
        // 如果非变异限制非零，则设置只读请求的分母为nonMutatingLimit，并记录日志。
        if nonMutatingLimit != 0 {
            watermark.readOnlyObserver.SetDenominator(float64(nonMutatingLimit))
            klog.V(2).InfoS("Set denominator for readonly requests", "limit", nonMutatingLimit)
        }

        // 如果变异限制非零，则设置变异请求的分母为mutatingLimit，并记录日志。
        if mutatingLimit != 0 {
            watermark.mutatingObserver.SetDenominator(float64(mutatingLimit))
            klog.V(2).InfoS("Set denominator for mutating requests", "limit", mutatingLimit)
        }
    })
}
```

### requestWatermark

```GO
// requestWatermark用于跟踪特定处理阶段的最大请求数量。
type requestWatermark struct {	
	phase string
    readOnlyObserver, mutatingObserver fcmetrics.RatioedGauge
    lock sync.Mutex
    readOnlyWatermark, mutatingWatermark int
}

// recordMutating函数用于记录可变操作的水位标记。
func (w *requestWatermark) recordMutating(mutatingVal int) {
	w.mutatingObserver.Set(float64(mutatingVal)) // 设置可变操作的观察值

	w.lock.Lock()
	defer w.lock.Unlock()

	if w.mutatingWatermark < mutatingVal {
		w.mutatingWatermark = mutatingVal // 更新可变操作的水位标记
	}
}

// recordReadOnly函数用于记录只读操作的水位标记。
func (w *requestWatermark) recordReadOnly(readOnlyVal int) {
	w.readOnlyObserver.Set(float64(readOnlyVal)) // 设置只读操作的观察值

	w.lock.Lock()
	defer w.lock.Unlock()

	if w.readOnlyWatermark < readOnlyVal {
		w.readOnlyWatermark = readOnlyVal // 更新只读操作的水位标记
	}
}
```

### priorityAndFairnessHandler

```GO
// priorityAndFairnessHandler用于处理具有优先级和公平性的请求。
type priorityAndFairnessHandler struct {
    handler http.Handler
    longRunningRequestCheck apirequest.LongRunningRequestCheck
    fcIfc utilflowcontrol.Interface
    workEstimator flowcontrolrequest.WorkEstimatorFunc

    // droppedRequests用于跟踪已丢弃请求的历史记录，以便计算RetryAfter标头以避免系统过载。
    droppedRequests utilflowcontrol.DroppedRequestsTracker
}

func (h *priorityAndFairnessHandler) Handle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestInfo, ok := apirequest.RequestInfoFrom(ctx)
	if !ok {
		handleError(w, r, fmt.Errorf("no RequestInfo found in context"))
		return
	}
	user, ok := apirequest.UserFrom(ctx)
	if !ok {
		handleError(w, r, fmt.Errorf("no User found in context"))
		return
	}

	isWatchRequest := watchVerbs.Has(requestInfo.Verb)

	// 如果是长时间运行的非watch请求，则跳过跟踪。
	if h.longRunningRequestCheck != nil && h.longRunningRequestCheck(r, requestInfo) && !isWatchRequest {
		klog.V(6).Infof("Serving RequestInfo=%#+v, user.Info=%#+v as longrunning\n", requestInfo, user)
		h.handler.ServeHTTP(w, r)
		return
	}

	var classification *PriorityAndFairnessClassification
	noteFn := func(fs *flowcontrol.FlowSchema, pl *flowcontrol.PriorityLevelConfiguration, flowDistinguisher string) {
        // 记录请求的优先级和公平性分类信息。
		classification = &PriorityAndFairnessClassification{
			FlowSchemaName:    fs.Name,
			FlowSchemaUID:     fs.UID,
			PriorityLevelName: pl.Name,
			PriorityLevelUID:  pl.UID,
		}
		// 将分类信息记录到日志中。
		httplog.AddKeyValue(ctx, "apf_pl", truncateLogField(pl.Name))
		httplog.AddKeyValue(ctx, "apf_fs", truncateLogField(fs.Name))
	}
	// estimateWork函数用于估算请求的工作量。
	estimateWork := func() flowcontrolrequest.WorkEstimate {
		if classification == nil {
			// 在请求的分类完成之前调用了workEstimator，这通常不应该发生。
			klog.ErrorS(fmt.Errorf("workEstimator is being invoked before classification of the request has completed"),
				"Using empty FlowSchema and PriorityLevelConfiguration name", "verb", r.Method, "URI", r.RequestURI)
			return h.workEstimator(r, "", "")
		}
		// 调用工作量估算函数来获取工作量估算结果。
		workEstimate := h.workEstimator(r, classification.FlowSchemaName, classification.PriorityLevelName)
		// 观察工作量估算结果的座位数。
		fcmetrics.ObserveWorkEstimatedSeats(classification.PriorityLevelName, classification.FlowSchemaName, workEstimate.MaxSeats())
        // 将工作量估算结果的相关信息记录到日志中。
		httplog.AddKeyValue(ctx, "apf_iseats", workEstimate.InitialSeats)
		httplog.AddKeyValue(ctx, "apf_fseats", workEstimate.FinalSeats)
		httplog.AddKeyValue(ctx, "apf_additionalLatency", workEstimate.AdditionalLatency)

		return workEstimate
	}

	var served bool
	isMutatingRequest := !nonMutatingRequestVerbs.Has(requestInfo.Verb)
    // noteExecutingDelta函数用于记录正在执行的请求数量的增量。
	noteExecutingDelta := func(delta int32) {
		if isMutatingRequest {
			watermark.recordMutating(int(atomic.AddInt32(&atomicMutatingExecuting, delta)))
		} else {
			watermark.recordReadOnly(int(atomic.AddInt32(&atomicReadOnlyExecuting, delta)))
		}
	}
    // noteWaitingDelta函数用于记录正在等待的请求数量的增量。
	noteWaitingDelta := func(delta int32) {
		if isMutatingRequest {
			waitingMark.recordMutating(int(atomic.AddInt32(&atomicMutatingWaiting, delta)))
		} else {
			waitingMark.recordReadOnly(int(atomic.AddInt32(&atomicReadOnlyWaiting, delta)))
		}
	}
    // queueNote函数根据是否在队列中将请求数量进行增减。
	queueNote := func(inQueue bool) {
		if inQueue {
			noteWaitingDelta(1)
		} else {
			noteWaitingDelta(-1)
		}
	}
	// 创建请求摘要对象，用于记录请求的相关信息。
	digest := utilflowcontrol.RequestDigest{
		RequestInfo: requestInfo,
		User:        user,
	}

	if isWatchRequest {
		// 创建一个用于阻塞调用handler.ServeHTTP()的通道，直到通道关闭，该通道在execute()函数中关闭。
		// 如果APF拒绝请求，则通道永远不会关闭。
		shouldStartWatchCh := make(chan struct{})

		watchInitializationSignal := newInitializationSignal()
		
		var watchReq *http.Request
		// 在执行execute()函数之前，将请求包装起来，并设置包含watchInitializationSignal的上下文，
		// 以便将其传递给存储层。
		var forgetWatch utilflowcontrol.ForgetWatchFunc
		// 在defer中确保执行一些清理操作，包括发送初始化信号和忘记watcher。
		defer func() {
			// 防止请求无法达到存储层并且初始化信号不会发送。
			if watchInitializationSignal != nil {
				watchInitializationSignal.Signal()
			}
			// 如果已注册watcher，则忘记它。
			// 这是无竞争的，因为此时已经发生以下情况之一：
			// case <-shouldStartWatchCh: execute()完成了对forgetWatch的赋值
			// case <-resultCh: Handle()完成，而Handle()在execute()运行时不返回
			if forgetWatch != nil {
				forgetWatch()
			}
		}()
		
        // execute函数用于执行watch请求。
		execute := func() {
			startedAt := time.Now()
			defer func() {
				httplog.AddKeyValue(ctx, "apf_init_latency", time.Since(startedAt))
			}()
            // 增加正在执行的请求数量。
			noteExecutingDelta(1)
			defer noteExecutingDelta(-1)
			served = true
			setResponseHeaders(classification, w)
			// 在注册watcher之前执行h.fcIfc.RegisterWatch(r)函数，并将forgetWatch赋值为返回的函数。
			forgetWatch = h.fcIfc.RegisterWatch(r)

			// 通知主线程已准备好启动watch。
			close(shouldStartWatchCh)

			// 等待请求从APF的角度完成（即初始化完成）。
			watchInitializationSignal.Wait()
		}

		// 确保可以异步将结果放入resultCh通道。
		resultCh := make(chan interface{}, 1)

		// 在单独的goroutine中调用Handle函数。
		// 之所以这样做是因为从APF的角度来看，请求处理完成的条件是watch初始化完成
		// （通常比watch请求本身快得多）。这意味着Handle()调用会更快地完成，
		// 出于性能的考虑，我们希望减少运行的goroutine数量-因此我们将较短的操作放在专用的goroutine中，
		// 将实际的watch处理程序放在主goroutine中。
		go func() {
			defer func() {
				err := recover()
				// 不包装sentinel ErrAbortHandler panic。
				if err != nil && err != http.ErrAbortHandler {
					// 与标准库http服务器代码相同。手动分配堆栈跟踪缓冲区大小以防止日志过大。
					const size = 64 << 10
					buf := make([]byte, size)
					buf = buf[:runtime.Stack(buf, false)]
					err = fmt.Sprintf("%v\n%s", err, buf)
				}

				// Ensure that the result is put into resultCh independently of the panic.
				resultCh <- err
			}()

			// 使用显式的取消函数创建handleCtx。
			// 原因是Handle()在底层可能会启动额外的goroutine，
			// 该goroutine在上下文取消时被阻塞。然而，从APF的角度来看，
			// 我们不希望等待整个watch请求处理完成（也就是上下文实际上被取消）-我们希望在请求从APF的角度处理完成时解除阻塞goroutine。
			//
			// 请注意，我们明确地不使用该上下文调用实际的处理程序，
			// 以避免过早地取消请求。
			handleCtx, handleCtxCancel := context.WithCancel(ctx)
			defer handleCtxCancel()

			// 注意，Handle函数将返回，无论请求执行还是被拒绝。
			// 如果被拒绝，该函数将在不调用传递的execute函数的情况下返回。
			h.fcIfc.Handle(handleCtx, digest, noteFn, estimateWork, queueNote, execute)
		}()

		select {
		case <-shouldStartWatchCh:
            // 使用带有watchInitializationSignal的上下文创建watchCtx。
			watchCtx := utilflowcontrol.WithInitializationSignal(ctx, watchInitializationSignal)
			watchReq = r.WithContext(watchCtx)
            // 调用handler.ServeHTTP()处理watch请求。
			h.handler.ServeHTTP(w, watchReq)
			// 在等待resultCh通道时，保护免受请求处理引发的恐慌的情况。
			// 在此之前，必须确保请求不会到达存储层并且初始化信号不会发送。
			watchInitializationSignal.Signal()
			// TODO: 还有其他的清理工作需要完成吗？例如，调用忘记watcher等。
			if err := <-resultCh; err != nil {
				panic(err)
			}
		case err := <-resultCh:
			if err != nil {
				panic(err)
			}
		}
	} else {
        // execute函数用于执行非watch请求。
		execute := func() {
            // 增加正在执行的请求数量。
			noteExecutingDelta(1)
			defer noteExecutingDelta(-1)
			served = true
			setResponseHeaders(classification, w)
			// 执行实际的请求处理程序。
			h.handler.ServeHTTP(w, r)
		}
		// 使用前面定义的参数调用Handle函数。
		h.fcIfc.Handle(ctx, digest, noteFn, estimateWork, queueNote, execute)
	}
	if !served {
	// 如果请求未被服务，则执行以下操作：
        setResponseHeaders(classification, w) // 设置响应头
        epmetrics.RecordDroppedRequest(r, requestInfo, epmetrics.APIServerComponent, isMutatingRequest) // 记录已丢弃的请求
        epmetrics.RecordRequestTermination(r, requestInfo, epmetrics.APIServerComponent, http.StatusTooManyRequests) // 记录请求终止
        h.droppedRequests.RecordDroppedRequest(classification.PriorityLevelName) // 记录已丢弃的请求
        // TODO（wojtek-t）：来自deads2k的想法：我们可以考虑进行一些抖动，在非整数的情况下，只返回截断后的结果，并在服务器端休眠剩余部分。
        tooManyRequests(r, w, strconv.Itoa(int(h.droppedRequests.GetRetryAfter(classification.PriorityLevelName)))) // 返回“请求过多”的响应
    }
}
```

## WithMaxInFlightLimit

用于限制了正在处理的请求的数量

```GO
// WithMaxInFlightLimit函数限制了正在处理的请求的数量，限制为传入通道的缓冲区大小。
func WithMaxInFlightLimit(
	handler http.Handler, // 处理程序
	nonMutatingLimit int, // 非变异请求的限制
	mutatingLimit int, // 变异请求的限制
	longRunningRequestCheck apirequest.LongRunningRequestCheck, // 检查长时间运行的请求
) http.Handler {
	if nonMutatingLimit == 0 && mutatingLimit == 0 {
		return handler
	}
	var nonMutatingChan chan bool
	var mutatingChan chan bool
	if nonMutatingLimit != 0 {
		nonMutatingChan = make(chan bool, nonMutatingLimit) // 创建非变异请求的通道
		klog.V(2).InfoS("Initialized nonMutatingChan", "len", nonMutatingLimit) // 输出日志：初始化非变异请求通道，长度为nonMutatingLimit
	} else {
		klog.V(2).InfoS("Running with nil nonMutatingChan") // 输出日志：运行时使用空的非变异请求通道
	}
	if mutatingLimit != 0 {
		mutatingChan = make(chan bool, mutatingLimit) // 创建变异请求的通道
		klog.V(2).InfoS("Initialized mutatingChan", "len", mutatingLimit) // 输出日志：初始化变异请求通道，长度为mutatingLimit
	} else {
		klog.V(2).InfoS("Running with nil mutatingChan") // 输出日志：运行时使用空的变异请求通道
	}
	initMaxInFlight(nonMutatingLimit, mutatingLimit) // 初始化最大并发请求数

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		requestInfo, ok := apirequest.RequestInfoFrom(ctx)
		if !ok {
			handleError(w, r, fmt.Errorf("no RequestInfo found in context, handler chain must be wrong")) // 处理错误：在上下文中未找到RequestInfo
			return
		}

		// 跳过跟踪长时间运行的事件。
		if longRunningRequestCheck != nil && longRunningRequestCheck(r, requestInfo) {
			handler.ServeHTTP(w, r) // 处理长时间运行的请求
			return
		}

		var c chan bool
		isMutatingRequest := !nonMutatingRequestVerbs.Has(requestInfo.Verb) // 判断请求是否为变异请求
		if isMutatingRequest {
			c = mutatingChan
		} else {
			c = nonMutatingChan
		}

		if c == nil {
			handler.ServeHTTP(w, r) // 处理请求
		} else {
			select {
			case c <- true:
				// 我们记录请求在服务期间和完成后的并发级别，因为两种状态都对并发采样统计数据有贡献。
				if isMutatingRequest {
					watermark.recordMutating(len(c)) // 记录变异操作的水位标记
				} else {
					watermark.recordReadOnly(len(c)) // 记录只读操作的水位标记
				}
				defer func() {
					<-c
					if isMutatingRequest {
						watermark.recordMutating(len(c)) // 记录变异操作的水位标记
					} else {
						watermark.recordReadOnly(len(c)) // 记录只读操作的水位标记
					}
				}()
				handler.ServeHTTP(w, r) // 处理请求

			default:
				// 此时我们即将返回429，但并非所有角色都应受到速率限制。系统：master非常强大，他们应始终获得答案。这是超级管理员或环回连接。
				if currUser, ok := apirequest.UserFrom(ctx); ok {
					for _, group := range currUser.GetGroups() {
						if group == user.SystemPrivilegedGroup {
							handler.ServeHTTP(w, r) // 处理请求
							return
						}
					}
				}
				// 我们需要将此数据在用于限流的桶之间分割。
				metrics.RecordDroppedRequest(r, requestInfo, metrics.APIServerComponent, isMutatingRequest) // 记录已丢弃的请求
				metrics.RecordRequestTermination(r, requestInfo, metrics.APIServerComponent, http.StatusTooManyRequests) // 记录请求终止
				tooManyRequests(r, w, retryAfter) // 处理请求过多的情况
			}
		}
	})
}

// tooManyRequests函数返回状态码为429（“Too Many Requests”）的响应。
func tooManyRequests(req *http.Request, w http.ResponseWriter, retryAfter string) {
	// 设置响应头，指示重试时间
	w.Header().Set("Retry-After", retryAfter)
	http.Error(w, "Too many requests, please try again later.", http.StatusTooManyRequests) // 返回状态码为429的响应
}
```

## WithImpersonation

用于实现请求的模拟操作

```GO
// WithImpersonation 是一个过滤器，用于检查并验证请求是否尝试更改其请求的 user.Info。
func WithImpersonation(handler http.Handler, a authorizer.Authorizer, s runtime.NegotiatedSerializer) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        // 构建要模拟的请求列表
        impersonationRequests, err := buildImpersonationRequests(req.Header)
        if err != nil {
            klog.V(4).Infof("%v", err)
            responsewriters.InternalError(w, req, err)
            return
        }
        // 如果没有模拟请求，则直接调用原始处理程序
        if len(impersonationRequests) == 0 {
            handler.ServeHTTP(w, req)
            return
    	}
       	ctx := req.Context()
        // 获取当前请求的用户信息
        requestor, exists := request.UserFrom(ctx)
        if !exists {
            responsewriters.InternalError(w, req, errors.New("no user found for request"))
            return
        }

        // 如果未指定 groups，则根据用户类型以不同方式查找它们
        // 如果已指定 groups，则它们是授权的权限（包括 system:authenticated/system:unauthenticated groups）
        groupsSpecified := len(req.Header[authenticationv1.ImpersonateGroupHeader]) > 0

        // 确保我们被允许模拟每个请求的对象。在迭代过程中构建用户名和组信息
        username := ""
        groups := []string{}
        userExtra := map[string][]string{}
        uid := ""
        for _, impersonationRequest := range impersonationRequests {
            // 获取模拟请求的 GroupVersionKind
            gvk := impersonationRequest.GetObjectKind().GroupVersionKind()
            actingAsAttributes := &authorizer.AttributesRecord{
                User:            requestor,
                Verb:            "impersonate",
                APIGroup:        gvk.Group,
                APIVersion:      gvk.Version,
                Namespace:       impersonationRequest.Namespace,
                Name:            impersonationRequest.Name,
                ResourceRequest: true,
            }

            switch gvk.GroupKind() {
            case v1.SchemeGroupVersion.WithKind("ServiceAccount").GroupKind():
                actingAsAttributes.Resource = "serviceaccounts"
                // 构建 ServiceAccount 的用户名
                username = serviceaccount.MakeUsername(impersonationRequest.Namespace, impersonationRequest.Name)
                if !groupsSpecified {
                    // 如果未指定 ServiceAccount 的 groups，则根据命名空间添加它们
                    groups = serviceaccount.MakeGroupNames(impersonationRequest.Namespace)
                }

            case v1.SchemeGroupVersion.WithKind("User").GroupKind():
                actingAsAttributes.Resource = "users"
                username = impersonationRequest.Name

            case v1.SchemeGroupVersion.WithKind("Group").GroupKind():
                actingAsAttributes.Resource = "groups"
                groups = append(groups, impersonationRequest.Name)

            case authenticationv1.SchemeGroupVersion.WithKind("UserExtra").GroupKind():
                extraKey := impersonationRequest.FieldPath
                extraValue := impersonationRequest.Name
                actingAsAttributes.Resource = "userextras"
                actingAsAttributes.Subresource = extraKey
                userExtra[extraKey] = append(userExtra[extraKey], extraValue)

            case authenticationv1.SchemeGroupVersion.WithKind("UID").GroupKind():
                uid = string(impersonationRequest.Name)
                actingAsAttributes.Resource = "uids"

            default:
                klog.V(4).InfoS("unknown impersonation request type", "request", impersonationRequest)
                responsewriters.Forbidden(ctx, actingAsAttributes, w, req, fmt.Sprintf("unknown impersonation request type: %v", impersonationRequest), s)
                return
            }

            // 验证模拟请求是否被授权
            decision, reason, err := a.Authorize(ctx, actingAsAttributes)
            if err != nil || decision != authorizer.DecisionAllow {
                klog.V(4).InfoS("Forbidden", "URI", req.RequestURI, "reason", reason, "err", err)
                responsewriters.Forbidden(ctx, actingAsAttributes, w, req, reason, s)
                return
            }
        }

        // 当模拟的用户不是匿名用户时，在模拟的用户信息中包含 'system:authenticated' 组
        // 条件：
        // - 如果未指定任何组
        // - 如果指定的组不是 'system:authenticated'
        if username != user.Anonymous {
            addAuthenticated := true
            for _, group := range groups {
                if group == user.AllAuthenticated || group == user.AllUnauthenticated {
                    addAuthenticated = false
                    break
                }
            }

            if addAuthenticated {
                groups = append(groups, user.AllAuthenticated)
            }
        } else {
            // 当模拟的用户是匿名用户时，在模拟的用户信息中包含 'system:unauthenticated' 组
            addUnauthenticated := true
            for _, group := range groups {
                if group == user.AllUnauthenticated {
                    addUnauthenticated = false
                    break
                }
            }

            if addUnauthenticated {
                groups = append(groups, user.AllUnauthenticated)
            }
        }

        // 创建新的 user.Info 对象，包含模拟的用户名、组、额外信息和 UID
        newUser := &user.DefaultInfo{
            Name:   username,
            Groups: groups,
            Extra:  userExtra,
            UID:    uid,
        }
        // 将新的 user.Info 对象添加到请求的上下文中
        req = req.WithContext(request.WithUser(ctx, newUser))

        // 记录日志
        oldUser, _ := request.UserFrom(ctx)
        httplog.LogOf(req, w).Addf("%v is acting as %v", oldUser, newUser)

        ae := audit.AuditEventFrom(ctx)
        audit.LogImpersonatedUser(ae, newUser)

        // 清除请求中的所有模拟请求的标头
        req.Header.Del(authenticationv1.ImpersonateUserHeader)
        req.Header.Del(authenticationv1.ImpersonateGroupHeader)
        req.Header.Del(authenticationv1.ImpersonateUIDHeader)
        for headerName := range req.Header {
            if strings.HasPrefix(headerName, authenticationv1.ImpersonateUserExtraHeaderPrefix) {
                req.Header.Del(headerName)
            }
        }

        // 调用原始处理程序
        handler.ServeHTTP(w, req)
    })
}

// unescapeExtraKey 函数用于解码编码的键。
func unescapeExtraKey(encodedKey string) string {
	// 使用 url.PathUnescape 函数对 %-encoded 的字节进行解码。
	key, err := url.PathUnescape(encodedKey)
	if err != nil {
		return encodedKey // 即使是格式错误或未编码的字符串，也始终记录额外的字符串。
	}
	return key
}

// buildImpersonationRequests 函数返回一个表示我们请求模拟的不同事物的对象引用列表。
// 还包括一个表示 user.Info.Extra 的 map[string][]string。
// 在切换上下文之前，必须对每个请求进行当前用户的授权。
func buildImpersonationRequests(headers http.Header) ([]v1.ObjectReference, error) {
	impersonationRequests := []v1.ObjectReference{} // 创建一个空的 v1.ObjectReference 列表。

	requestedUser := headers.Get(authenticationv1.ImpersonateUserHeader) // 获取请求头中的用户。
	hasUser := len(requestedUser) > 0 // 检查是否存在用户。

	if hasUser {
		if namespace, name, err := serviceaccount.SplitUsername(requestedUser); err == nil {
			// 如果 requestedUser 是以 namespace/name 的格式，将其分割并创建一个 ServiceAccount 对象引用，然后将其添加到 impersonationRequests 列表中。
			impersonationRequests = append(impersonationRequests, v1.ObjectReference{Kind: "ServiceAccount", Namespace: namespace, Name: name})
		} else {
			// 否则，将 requestedUser 作为用户名创建一个 User 对象引用，然后将其添加到 impersonationRequests 列表中。
			impersonationRequests = append(impersonationRequests, v1.ObjectReference{Kind: "User", Name: requestedUser})
		}
	}

	hasGroups := false // 用于标记是否存在组。
	for _, group := range headers[authenticationv1.ImpersonateGroupHeader] {
		hasGroups = true // 存在组，将 hasGroups 标记为 true。
		// 创建一个 Group 对象引用，然后将其添加到 impersonationRequests 列表中。
		impersonationRequests = append(impersonationRequests, v1.ObjectReference{Kind: "Group", Name: group})
	}

	hasUserExtra := false // 用于标记是否存在额外的用户信息。
	for headerName, values := range headers {
		if !strings.HasPrefix(headerName, authenticationv1.ImpersonateUserExtraHeaderPrefix) {
			continue // 如果不是以指定前缀开头的请求头，跳过。
		}

		hasUserExtra = true // 存在额外的用户信息，将 hasUserExtra 标记为 true。
		extraKey := unescapeExtraKey(strings.ToLower(headerName[len(authenticationv1.ImpersonateUserExtraHeaderPrefix):]))
		// 解析额外的键并进行小写处理。

		// 为每个额外的值创建单独的请求。
		for _, value := range values {
			// 创建一个 UserExtra 对象引用，并将其添加到 impersonationRequests 列表中。
			impersonationRequests = append(impersonationRequests,
				v1.ObjectReference{
					Kind: "UserExtra",
					// 上面我们只解析了一个组，但如果没有某个版本，解析将失败，因此使用内部版本将有助于我们在有人开始使用它时失败。
					APIVersion: authenticationv1.SchemeGroupVersion.String(),
					Name:       value,
					// ObjectReference 没有 subresource 字段，FieldPath 是一个可用的字段，因此我们将使用它。
					// TODO 为 ObjectReference 引用资源和子资源进行改进。
					FieldPath: extraKey,
				})
		}
	}

	requestedUID := headers.Get(authenticationv1.ImpersonateUIDHeader) // 获取请求头中的 UID。
	hasUID := len(requestedUID) > 0 // 检查是否存在 UID。

	if hasUID {
		// 创建一个 UID 对象引用，并将其添加到 impersonationRequests 列表中。
		impersonationRequests = append(impersonationRequests, v1.ObjectReference{
			Kind:       "UID",
			Name:       requestedUID,
			APIVersion: authenticationv1.SchemeGroupVersion.String(),
		})
	}

	if (hasGroups || hasUserExtra || hasUID) && !hasUser {
		// 如果存在组、额外的用户信息或 UID，但没有用户，则返回错误。
		return nil, fmt.Errorf("requested %v without impersonating a user", impersonationRequests)
	}

	return impersonationRequests, nil // 返回构建的 impersonationRequests 列表。
}  
```

## WithAudit

用于为所有请求到达服务器的 http.Handler 添加审计日志信息

```GO
// WithAudit 函数用于为所有请求到达服务器的 http.Handler 添加审计日志信息。
// 审计级别根据请求的属性和审计策略决定。日志会被发送到审计接收器以处理事件。
// 如果接收器或审计策略为 nil，则不进行装饰。
func WithAudit(handler http.Handler, sink audit.Sink, policy audit.PolicyRuleEvaluator, longRunningCheck request.LongRunningRequestCheck) http.Handler {
	if sink == nil || policy == nil {
		return handler // 如果接收器或审计策略为 nil，则直接返回原始 handler。
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ac, err := evaluatePolicyAndCreateAuditEvent(req, policy)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("failed to create audit event: %v", err))
			responsewriters.InternalError(w, req, errors.New("failed to create audit event"))
			return
		}

		if ac == nil || ac.Event == nil {
			handler.ServeHTTP(w, req) // 如果 ac 或 ac.Event 为 nil，则直接调用原始 handler。
			return
		}
		ev := ac.Event

		ctx := req.Context()
		omitStages := ac.RequestAuditConfig.OmitStages

		ev.Stage = auditinternal.StageRequestReceived
		if processed := processAuditEvent(ctx, sink, ev, omitStages); !processed {
			audit.ApiserverAuditDroppedCounter.WithContext(ctx).Inc()
			responsewriters.InternalError(w, req, errors.New("failed to store audit event"))
			return
		}

		// 拦截状态码
		var longRunningSink audit.Sink
		if longRunningCheck != nil {
			ri, _ := request.RequestInfoFrom(ctx)
			if longRunningCheck(req, ri) {
				longRunningSink = sink
			}
		}
		respWriter := decorateResponseWriter(ctx, w, ev, longRunningSink, omitStages)

		// 在离开该函数时发送审计事件，无论是通过 panic 还是正常完成。
		// 对于长时间运行的请求，这将是第二个审计事件。
		defer func() {
			if r := recover(); r != nil {
				defer panic(r)
				ev.Stage = auditinternal.StagePanic
				ev.ResponseStatus = &metav1.Status{
					Code:    http.StatusInternalServerError,
					Status:  metav1.StatusFailure,
					Reason:  metav1.StatusReasonInternalError,
					Message: fmt.Sprintf("APIServer panic'd: %v", r),
				}
				processAuditEvent(ctx, sink, ev, omitStages)
				return
			}

			// 如果没有发送 StageResponseStarted 事件，因为没有发送状态码或响应主体，则在这里进行伪装。
			// 但是只有在调用 http.ResponseWriter.WriteHeader 时才会发送 Audit-Id HTTP 头。
			fakedSuccessStatus := &metav1.Status{
				Code:    http.StatusOK,
				Status:  metav1.StatusSuccess,
				Message: "Connection closed early",
			}
			if ev.ResponseStatus == nil && longRunningSink != nil {
				ev.ResponseStatus = fakedSuccessStatus
				ev.Stage = auditinternal.StageResponseStarted
				processAuditEvent(ctx, longRunningSink, ev, omitStages)
			}

			ev.Stage = auditinternal.StageResponseComplete
			if ev.ResponseStatus == nil {
				ev.ResponseStatus = fakedSuccessStatus
			}
			processAuditEvent(ctx, sink, ev, omitStages)
		}()
		handler.ServeHTTP(respWriter, req) // 调用原始 handler，并将装饰后的 respWriter 作为参数传递。
	})
}

// Sink 接口定义了处理事件的方法。
type Sink interface {
	// ProcessEvents 处理事件。对于每个审计 ID，可能会调用 ProcessEvents 多达三次。
	// 错误可能由接收器自身记录。如果错误是致命的，导致内部错误，则 ProcessEvents 应该 panic。
	// 事件不能被更改，调用返回后由调用者重用，因此接收器必须进行深拷贝以保留副本（如果需要）。
	// 成功时返回 true，可能在出错时返回 false。
	ProcessEvents(events ...*auditinternal.Event) bool
}

// PolicyRuleEvaluator 接口公开了评估策略规则的方法。
type PolicyRuleEvaluator interface {
	// EvaluatePolicyRule 评估 apiserver 的审计策略与给定的授权属性相匹配的审计配置，并返回适用于给定请求的审计配置。
	EvaluatePolicyRule(authorizer.Attributes) RequestAuditConfig
}
```

### evaluatePolicyAndCreateAuditEvent

```GO
// evaluatePolicyAndCreateAuditEvent 负责评估适用于请求的审计策略配置，并创建一个新的审计事件，将其写入 API 审计日志。
// - 如果发生任何错误，则返回错误。
func evaluatePolicyAndCreateAuditEvent(req *http.Request, policy audit.PolicyRuleEvaluator) (*audit.AuditContext, error) {
	ctx := req.Context()
	ac := audit.AuditContextFrom(ctx)
	if ac == nil {
		// 审计未启用。
		return nil, nil
	}

	attribs, err := GetAuthorizerAttributes(ctx)
	if err != nil {
		return ac, fmt.Errorf("failed to GetAuthorizerAttributes: %v", err)
	}

	rac := policy.EvaluatePolicyRule(attribs)
	audit.ObservePolicyLevel(ctx, rac.Level)
	ac.RequestAuditConfig = rac
	if rac.Level == auditinternal.LevelNone {
		// 不进行审计。
		return ac, nil
	}

	requestReceivedTimestamp, ok := request.ReceivedTimestampFrom(ctx)
	if !ok {
		requestReceivedTimestamp = time.Now()
	}
	ev, err := audit.NewEventFromRequest(req, requestReceivedTimestamp, rac.Level, attribs)
	if err != nil {
		return nil, fmt.Errorf("failed to complete audit event from request: %v", err)
	}

	ac.Event = ev

	return ac, nil
}
```

#### NewEventFromRequest

```GO
// NewEventFromRequest 从请求中创建一个新的审计事件，并设置相关字段。
func NewEventFromRequest(req *http.Request, requestReceivedTimestamp time.Time, level auditinternal.Level, attribs authorizer.Attributes) (*auditinternal.Event, error) {
	ev := &auditinternal.Event{
		RequestReceivedTimestamp: metav1.NewMicroTime(requestReceivedTimestamp),
		Verb:                     attribs.GetVerb(),
		RequestURI:               req.URL.RequestURI(),
		UserAgent:                maybeTruncateUserAgent(req),
		Level:                    level,
	}

	auditID, found := AuditIDFrom(req.Context())
	if !found {
		auditID = types.UID(uuid.New().String())
	}
	ev.AuditID = auditID

	ips := utilnet.SourceIPs(req)
	ev.SourceIPs = make([]string, len(ips))
	for i := range ips {
		ev.SourceIPs[i] = ips[i].String()
	}

	if user := attribs.GetUser(); user != nil {
		ev.User.Username = user.GetName()
		ev.User.Extra = map[string]authnv1.ExtraValue{}
		for k, v := range user.GetExtra() {
			ev.User.Extra[k] = authnv1.ExtraValue(v)
		}
		ev.User.Groups = user.GetGroups()
		ev.User.UID = user.GetUID()
	}

	if attribs.IsResourceRequest() {
		ev.ObjectRef = &auditinternal.ObjectReference{
			Namespace:   attribs.GetNamespace(),
			Name:        attribs.GetName(),
			Resource:    attribs.GetResource(),
			Subresource: attribs.GetSubresource(),
			APIGroup:    attribs.GetAPIGroup(),
			APIVersion:  attribs.GetAPIVersion(),
		}
	}

	addAuditAnnotationsFrom(req.Context(), ev)

	return ev, nil
}
```

### auditResponseWriter

```GO
var _ http.ResponseWriter = &auditResponseWriter{}
var _ responsewriter.UserProvidedDecorator = &auditResponseWriter{}

// auditResponseWriter拦截WriteHeader，并在事件中设置响应状态码。如果设置了sink，则立即创建事件（适用于长时间运行的请求）。
type auditResponseWriter struct {
    http.ResponseWriter
    ctx        context.Context
    event      *auditinternal.Event
    once       sync.Once
    sink       audit.Sink
    omitStages []auditinternal.Stage
}

func (a *auditResponseWriter) Unwrap() http.ResponseWriter {
    return a.ResponseWriter
}

func (a *auditResponseWriter) processCode(code int) {
    // 使用sync.Once确保只执行一次
    a.once.Do(func() {
        // 如果事件的ResponseStatus为空，则创建一个ResponseStatus对象
        if a.event.ResponseStatus == nil {
            a.event.ResponseStatus = &metav1.Status{}
        }
        // 设置事件的响应状态码
        a.event.ResponseStatus.Code = int32(code)
        // 设置事件的Stage为StageResponseStarted
        a.event.Stage = auditinternal.StageResponseStarted

        // 如果设置了sink，则处理事件
        if a.sink != nil {
            processAuditEvent(a.ctx, a.sink, a.event, a.omitStages)
        }
    })
}

func (a *auditResponseWriter) Write(bs []byte) (int, error) {
    // Go库在没有写入状态码的情况下会在内部调用WriteHeader，但我们无法察觉到这一点
    // 处理状态码
    a.processCode(http.StatusOK)
    // 调用原始ResponseWriter的Write方法
    return a.ResponseWriter.Write(bs)
}

func (a *auditResponseWriter) WriteHeader(code int) {
    // 处理状态码
    a.processCode(code)
    // 调用原始ResponseWriter的WriteHeader方法
    a.ResponseWriter.WriteHeader(code)
}

func (a *auditResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
    // 在协议切换发生之前，伪造一个响应状态
    // 处理状态码
    a.processCode(http.StatusSwitchingProtocols)

    // 如果内部的ResponseWriter对象实现了http.Hijacker，则由WrapForHTTP1Or2返回的外部ResponseWriter对象也实现http.Hijacker
    return a.ResponseWriter.(http.Hijacker).Hijack()
}
```

#### processAuditEvent

```GO
func processAuditEvent(ctx context.Context, sink audit.Sink, ev *auditinternal.Event, omitStages []auditinternal.Stage) bool {
    // 遍历omitStages切片
    for _, stage := range omitStages {
        // 如果ev的Stage与当前遍历的stage相等
        if ev.Stage == stage {
            // 返回true
            return true
        }
    }

    // 根据ev的Stage进行不同的操作
    switch {
    // 如果ev的Stage为StageRequestReceived
    case ev.Stage == auditinternal.StageRequestReceived:
        // 将ev的StageTimestamp设置为ev的RequestReceivedTimestamp的微秒级时间
        ev.StageTimestamp = metav1.NewMicroTime(ev.RequestReceivedTimestamp.Time)
    // 如果ev的Stage为StageResponseComplete
    case ev.Stage == auditinternal.StageResponseComplete:
        // 将ev的StageTimestamp设置为当前时间的微秒级时间
        ev.StageTimestamp = metav1.NewMicroTime(time.Now())
        // 将延迟写入注释中
        writeLatencyToAnnotation(ctx, ev)
    // 默认情况
    default:
        // 将ev的StageTimestamp设置为当前时间的微秒级时间
        ev.StageTimestamp = metav1.NewMicroTime(time.Now())
    }

    // 观察事件
    audit.ObserveEvent(ctx)
    // 处理事件
    return sink.ProcessEvents(ev)
}
```

### decorateResponseWriter

```GO
func decorateResponseWriter(ctx context.Context, responseWriter http.ResponseWriter, ev *auditinternal.Event, sink audit.Sink, omitStages []auditinternal.Stage) http.ResponseWriter {
    // 创建auditResponseWriter对象
    delegate := &auditResponseWriter{
        ctx:            ctx,
        ResponseWriter: responseWriter,
        event:          ev,
        sink:           sink,
        omitStages:     omitStages,
    }

    // 包装为HTTP1或HTTP2的responsewriter
    return responsewriter.WrapForHTTP1Or2(delegate)
}
```

