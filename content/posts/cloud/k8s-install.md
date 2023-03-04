---
title: "k8s集群安装"
date: 2022-09-21T22:03:20+08:00
draft: false
toc: true
categories: [cloud]
tags: [kubernetes]
authors:
    - haiyux
featuredImagePreview: /img/k8s.webp
---

## 虚拟机准备

我这里准备了三台虚拟机，分别部署一个master和两个node，操作系统位ubuntu 20.04。**以下为特殊说明为三台机器都要做此操作**

## 安装容器runtime

 之前，我们用的容器runtime基本都是docker，但是docker并没有实现k8s的CRI，是在kubelet的有一个组件叫docker-shim做转化，在kubernetes v1.24版本以上这个组件已经废弃，这里选择containerd做容器runtime。当然，containerd是可以使用docker的镜像的。如果非要使用docker的话，被kubernetes废弃的docker-shim被docker自己维护起来了，可以试试看。但是不建议纯纯的浪费资源。

### 安装

```bash
apt install -y containerd
```

**生成默认配置**

```bash
mkdir /etc/containerd
containerd config default > /etc/containerd/config.toml
```

**配置`systemd cgroup`驱动程序**

```bash
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' /etc/containerd/config.toml
```

**设置代理和修改pause镜像**

重所周知的原因

- 镜像加速

我这里用的网易docker源 你也可以用别的 阿里源等

> 限免的的 `https://xxxxx.mirror.aliyuncs.com` 是阿里云加速，xxxx是我屏蔽字段
>
>https://cr.console.aliyun.com/cn-hangzhou/instances/mirrors 可以自啊这个地址申请自己的

```bash
sed -i 's|config_path = ""|config_path = "/etc/containerd/certs.d/"|g' /etc/containerd/config.toml

mkdir -p /etc/containerd/certs.d/docker.io
mkdir -p /etc/containerd/certs.d/docker.io
cat >/etc/containerd/certs.d/docker.io/hosts.toml <<EOF
server = "https://docker.io"
[host."https://xxxxx.mirror.aliyuncs.com"]
  capabilities = ["pull","resolve"]
[host."https://docker.mirrors.ustc.edu.cn"]
  capabilities = ["pull","resolve"]
[host."https://registry-1.docker.io"]
  capabilities = ["pull","resolve","push"]
EOF
```

- 把sandbox_image 修改成阿里云镜像版本自己看着办 不然kube-apiserver可能起不来

```bash
vim /etc/containerd/config.toml
sandbox_image = "registry.aliyuncs.com/google_containers/pause:3.8"
```

**启动**

```bash
systemctl daemon-reload
systemctl enable containerd
systemctl start containerd
```

### 测试

这里使用 `nerdctl`工具测试

`nerdctl` 是 containerd 房官方提供的加强版命令行工具 [https://github.com/containerd/nerdctl](https://github.com/containerd/nerdctl)

下载方式

```bash
wget https://ghproxy.com/https://github.com/containerd/nerdctl/releases/download/v0.23.0/nerdctl-0.23.0-linux-amd64.tar.gz

tar xzvf nerdctl-0.23.0-linux-amd64.tar.gz -C /usr/local/bin
```



```
nerdctl --debug pull busybox

DEBU[0000] verification process skipped                 
DEBU[0000] Found hosts dir "/etc/containerd/certs.d"    
DEBU[0000] Ignoring hosts dir "/etc/docker/certs.d"      error="stat /etc/docker/certs.d: no such file or directory"
DEBU[0000] The image will be unpacked for platform {"amd64" "linux" "" [] ""}, snapshotter "overlayfs". 
DEBU[0000] fetching                                      image="docker.io/library/busybox:latest"
DEBU[0000] loading host directory                        dir=/etc/containerd/certs.d/docker.io
DEBU[0000] resolving                                     host=hub-mirror.c.163.com
DEBU[0000] do request                                    host=hub-mirror.c.163.com request.header.accept="application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, */*" request.header.user-agent=containerd/1.6.0+unknown request.method=HEAD url="http://hub-mirror.c.163.com/v2/library/busybox/manifests/latest?ns=docker.io"
```

看到 host=hub-mirror.c.163.com 代表配置成功

## 其他准备工作

### 防火墙

```bash
# 查看状态
ufw status
# 如果打开着呢 请关闭
ufw disable
```

### 时间同步

```bash
apt install -y ntpdate
ntpdate time.windows.com
```

### 关闭swap分区

```
# 永久生效 需要重启
sed -ri 's/.*swap.*/#&/' /etc/fstab
# 临时关闭，重启后无效
swapoff -a
```

### 将桥接的IPv4流量传递到iptables的链

1. 在每个节点上将桥接的IPv4流量传递到iptables的链

```bash
cat > /etc/sysctl.d/k8s.conf << EOF
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
vm.swappiness = 0
EOF
```

```bash
# 加载br_netfilter模块
modprobe br_netfilter
# 查看是否加载
lsmod | grep br_netfilter
# 生效
sysctl --system

echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables
```

### 开启ipvs

在kubernetes中service有两种代理模型，一种是基于iptables，另一种是基于ipvs的。ipvs的性能要高于iptables的，但是如果要使用它，需要手动载入ipvs模块。
```bash
apt install -y  ipset ipvsadm

mkdir -p /etc/sysconfig/modules
cat > /etc/sysconfig/modules/ipvs.modules <<EOF
#!/bin/bash
modprobe -- ip_vs
modprobe -- ip_vs_rr
modprobe -- ip_vs_wrr
modprobe -- ip_vs_sh
modprobe -- nf_conntrack
EOF
```

**授权、运行、检查是否加载**

```
chmod 755 /etc/sysconfig/modules/ipvs.modules && bash /etc/sysconfig/modules/ipvs.modules && lsmod | grep -e ip_vs -e nf_conntrack_ipv4
```

**检查是否加载**

```
lsmod | grep -e ipvs -e nf_conntrack

sysctl --system
```

###  设置主机名

**设置主机名**

```
hostnamectl set-hostname <hostname>
```

**三台机器分别为**

```
# 192.168.56.100
hostnamectl set-hostname k8s-master

# 192.168.56.101
hostnamectl set-hostname k8s-node1

# 192.168.56.102
hostnamectl set-hostname k8s-node2
```

## 安装kubeadm、kubelet和kubectl

**安装https工具**

```bash
apt install -y apt-transport-https ca-certificates curl
```

**下载阿里云cloud公钥**

为什么下载阿里云的，不去下载 kubernetes 官方的 你懂得

```
sudo curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://mirrors.aliyun.com/kubernetes/apt/doc/apt-key.gpg
```

**添加 Kubernetes `apt` 仓库**

```
echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://mirrors.aliyun.com/kubernetes/apt/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list
```

**更新 `apt` 包索引，安装 kubelet、kubeadm 和 kubectl，并锁定其版本：**

```shell
apt update
apt install -y kubelet kubeadm kubectl
apt-mark hold kubelet kubeadm kubectl
```

## 查看k8s所需镜像

```
kubeadm config images list

egistry.k8s.io/kube-apiserver:v1.25.2
registry.k8s.io/kube-controller-manager:v1.25.2
registry.k8s.io/kube-scheduler:v1.25.2
registry.k8s.io/kube-proxy:v1.25.2
registry.k8s.io/pause:3.8
registry.k8s.io/etcd:3.5.4-0
registry.k8s.io/coredns/coredns:v1.9.3
```

## 初始化（只有master执行）

如果带上debug日志可以在后面加 --v=9

```
kubeadm init \
  --apiserver-advertise-address=192.168.56.100 \
  --image-repository registry.aliyuncs.com/google_containers \
  --kubernetes-version v1.25.2 \
  --service-cidr=10.96.0.0/12 \
  --pod-network-cidr=10.244.0.0/16
```

出现这个代表 init 成功

```
Your Kubernetes control-plane has initialized successfully!

To start using your cluster, you need to run the following as a regular user:

  mkdir -p $HOME/.kube
  sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
  sudo chown $(id -u):$(id -g) $HOME/.kube/config

Alternatively, if you are the root user, you can run:

  export KUBECONFIG=/etc/kubernetes/admin.conf

You should now deploy a pod network to the cluster.
Run "kubectl apply -f [podnetwork].yaml" with one of the options listed at:
  https://kubernetes.io/docs/concepts/cluster-administration/addons/

Then you can join any number of worker nodes by running the following on each as root:

kubeadm join 192.168.56.100:6443 --token qsmewy.fd3hlnkr6b3tb570 \
        --discovery-token-ca-cert-hash sha256:08afdf5077a0ee0f72553640e09356f19846d030552c35357d05032f95a14b89
```

根据提示执行

```bash
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

根据提示在两台node上执行命令 加入集群（**这个写你自己master弹出来的命令**）

```
kubeadm join 192.168.56.100:6443 --token qsmewy.fd3hlnkr6b3tb570 \
        --discovery-token-ca-cert-hash sha256:08afdf5077a0ee0f72553640e09356f19846d030552c35357d05032f95a14b89
```

出现这个代表节点加入集群成功

```
This node has joined the cluster:
* Certificate signing request was sent to apiserver and a response was received.
* The Kubelet was informed of the new secure connection details.

Run 'kubectl get nodes' on the control-plane to see this node join the cluster.
```

## 部署CNI网络插件

- kubernetes支持多种网络插件，比如flannel、calico、canal等，任选一种即可，本次选择flannel

```bash
kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml
```

这个是网络地址，可能是失败这里提供一个yaml下载，然后 apply，[kube-flannel.yml](/files/yaml/kube-flannel.yml)

## 测试

```bash
kubectl get node

NAME         STATUS   ROLES           AGE   VERSION
k8s-master   Ready    control-plane   31m   v1.25.2
k8s-node1    Ready    <none>          31m   v1.25.2
k8s-node2    Ready    <none>          30m   v1.25.2

kubectl get pod -n kube-system

NAME                                 READY   STATUS    RESTARTS   AGE
coredns-c676cc86f-chtqm              1/1     Running   0          31m
coredns-c676cc86f-ph8wl              1/1     Running   0          31m
etcd-k8s-master                      1/1     Running   1          32m
kube-apiserver-k8s-master            1/1     Running   1          32m
kube-controller-manager-k8s-master   1/1     Running   1          32m
kube-proxy-949st                     1/1     Running   0          31m
kube-proxy-9zjnb                     1/1     Running   0          31m
kube-proxy-g98kp                     1/1     Running   0          31m
kube-scheduler-k8s-master            1/1     Running   1          32m

kubectl get pod -n kube-flannel

NAME                    READY   STATUS    RESTARTS   AGE
kube-flannel-ds-jk8fp   1/1     Running   0          2m2s
kube-flannel-ds-pmmcs   1/1     Running   0          2m2s
kube-flannel-ds-r5j7s   1/1     Running   0          2m2s
```

创建一个 nginx pod

```bash
kubectl run nginx --image=nginx:1.17.1

kubectl get pod -owide
NAME    READY   STATUS    RESTARTS   AGE   IP           NODE        NOMINATED NODE   READINESS GATES
nginx   1/1     Running   0          27s   10.244.1.2   k8s-node1   <none>           <none>
```

创建一个 service

```yaml
# vim nginx-svc.yaml

apiVersion: v1
kind: Service
metadata:
  name: nginx
spec:
  type: ClusterIP
  ports:
    - port: 8080
      targetPort: 80
      protocol: TCP
      name: http
  selector:
    run: nginx
```

```
kubectl apply -f nginx-svc.yaml
kubectl get svc

NAME         TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
kubernetes   ClusterIP   10.96.0.1       <none>        443/TCP    43m
nginx        ClusterIP   10.110.94.194   <none>        8080/TCP   92s
```



## 之后加入node

master执行

```bash
kubeadm token create --ttl 0 --print-join-command
```

执行打印出来的命令
