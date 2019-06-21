#!/bin/bash
#set -u
#set -x

## Change shell for users
sudo sed -i 's/tcsh/bash/' /etc/passwd

WORKINGDIR='/mnt/extra/'
username=$(id -nu)
usergid=$(id -ng)
experimentid=$(hostname|cut -d '.' -f 2)
projectid=$usergid

sudo chown ${username}:${usergid} ${WORKINGDIR}/ -R
cd $WORKINGDIR
exec >> ${WORKINGDIR}/deploy.log
exec 2>&1

KUBEHOME="${WORKINGDIR}/kube/"
DEPLOY_CONFIG="${WORKINGDIR}/cloudlab-k8s-profile/$K8SVERSION/kube-deploy-yaml/"
mkdir -p $KUBEHOME && cd $KUBEHOME
export KUBECONFIG=$KUBEHOME/admin.conf

cd $WORKINGDIR

### Commands from RIC infra install
### ric-infra/00-Kubernetes/etc/infra.rc
# modify below for RIC infrastructure (docker-k8s-helm) component versions
INFRA_DOCKER_VERSION="18.06.1"
INFRA_K8S_VERSION="1.13.3"
INFRA_CNI_VERSION="0.6.0"
INFRA_HELM_VERSION="2.12.3"

### ric-infra/00-Kubernetes/etc/env.rc
# customize the following repo info to local infrastructure
# Gerrit code repo server
gerrithost=""
# Gerrit code repo server IP
gerritip=""

# Docker registry host name
dockerregistry=""
# Docker registry IP (if need to create local /etc/hosts entry)
dockerip=""
# Docker registry port
dockerport=""
# Docker registry user name
dockeruser=""
# Docker registry password
dockerpassword=""
# Docker registry CA certifiacte (if using self-signed cert)
dockercert=''

# Helm repo host name
helmrepo=helm.ricinfra.local
# Helm repo port
helmport=""
# Helm repo IP (if need to create local /etc/hosts entry)
helmip=""
# Helm repo user name
helmuser=""
# Helm repo password
helmpassword=""
# Helm repo CA certifiacte (if using self-signed cert)
helmcert=''


### ric-infra/00-Kubernetes/heat/scripts/k8s_vm_install.sh

DOCKERV="${INFRA_DOCKER_VERSION}"
KUBEV="${INFRA_K8S_VERSION}"
KUBECNIV="${INFRA_CNI_VERSION}"

KUBEVERSION="${KUBEV}-00"
CNIVERSION="${KUBECNIV}-00"
DOCKERVERSION="${DOCKERV}-0ubuntu1.2~18.04.1"

# disable swap
SWAPFILES=$(grep swap /etc/fstab | sed '/^#/ d' |cut -f1 -d' ')
if [ ! -z $SWAPFILES ]; then
  for SWAPFILE in $SWAPFILES
  do
    if [ ! -z $SWAPFILE ]; then
      echo "disabling swap file $SWAPFILE"
      if [[ $SWAPFILE == UUID* ]]; then
        UUID=$(echo $SWAPFILE | cut -f2 -d'=')
        swapoff -U $UUID
      else
        swapoff $SWAPFILE
      fi
      # edit /etc/fstab file, remove line with /swapfile
      sed -i -e "/$SWAPFILE/d" /etc/fstab
    fi
  done
fi

### Install packages & configure them
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
sudo apt-get -y update
sudo apt-get -y install software-properties-common
sudo apt-add-repository "deb http://apt.kubernetes.io/ kubernetes-xenial main"
echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee -a /etc/apt/sources.list.d/kubernetes.list

# install low latency kernel, docker.io, and kubernetes
sudo apt-get -y update
#### TODO instal low latency kernel
### sudo apt-get install -y linux-image-4.15.0-45-lowlatency curl jq netcat docker.io=${DOCKERVERSION}
sudo apt-get install -y curl jq netcat docker.io=${DOCKERVERSION}
sudo apt-get install -y kubernetes-cni=${CNIVERSION}
sudo apt-get install -y --allow-unauthenticated kubeadm=${KUBEVERSION} kubelet=${KUBEVERSION} kubectl=${KUBEVERSION}
sudo apt-mark hold kubernetes-cni kubelet kubeadm kubectl

# test access to k8s docker registry
sudo kubeadm config images pull


# non-master nodes have hostnames starting with s
if [[ $(hostname) == s* ]]; then
  echo "Done for non-master node"
  echo "Starting an NC TCP server on port 29999 to indicate we are ready"
  nc -l -p 29999 &
else 
  # below are steps for initializating master node, only run on the master node.  
  # minion node join will be triggered from the caller of the stack creation as ssh command.


  # create kubenetes config file
  if [[ ${KUBEV} == 1.13.* ]]; then
    cat <<EOF >"${WORKINGDIR}/config.yaml"
apiVersion: kubeadm.k8s.io/v1alpha3
kubernetesVersion: v${KUBEV}
kind: ClusterConfiguration
apiServerExtraArgs:
  feature-gates: SCTPSupport=true
networking:
  dnsDomain: cluster.local
  podSubnet: 10.244.0.0/16
  serviceSubnet: 10.96.0.0/12

---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: ipvs
EOF

  elif [[ ${KUBEV} == 1.14.* ]]; then
    cat <<EOF >"${WORKINGDIR}/config.yaml"
apiVersion: kubeadm.k8s.io/v1beta1
kubernetesVersion: v${KUBEV}
kind: ClusterConfiguration
apiServerExtraArgs:
  feature-gates: SCTPSupport=true
networking:
  dnsDomain: cluster.local
  podSubnet: 10.244.0.0/16
  serviceSubnet: 10.96.0.0/12

---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: ipvs
EOF

  else
    echo "Unsupported Kubernetes version requested.  Bail."
    exit
  fi


  # create a RBAC file for helm (tiller)
  cat <<EOF > "${WORKINGDIR}/rbac-config.yaml"
apiVersion: v1
kind: ServiceAccount
metadata:
  name: tiller
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: tiller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: tiller
    namespace: kube-system
EOF

  # start cluster (make sure CIDR is enabled with the flag)
  kubeadm init --config "${WORKINGDIR}/config.yaml"
fi


echo "FINISHED part copied from RIC"
exit 0
###############
###############
###############
###############


version=$(echo $(echo $K8SVERSION |sed 's/v//')-00)
sudo apt install -y docker.io=18.06.1-0ubuntu1.2~18.04.1 
sudo systemctl start docker
sudo systemctl enable docker
sudo apt-get install -y kubernetes-cni=0.6.0-00 golang-go jq 
sudo docker version
sudo swapoff -a

sudo apt-get install -qy kubelet=$version kubectl=$version kubeadm=$version
sudo kubeadm config images pull
sudo kubeadm init --pod-network-cidr=192.168.0.0/16 --kubernetes-version="$K8SVERSION" --ignore-preflight-errors='KubeletVersion'

# result will be like:  kubeadm join 155.98.36.111:6443 --token i0peso.pzk3vriw1iz06ruj --discovery-token-ca-cert-hash sha256:19c5fdee6189106f9cb5b622872fe4ac378f275a9d2d2b6de936848215847b98

# https://github.com/kubernetes/kubernetes/issues/44665
sudo cp /etc/kubernetes/admin.conf $KUBEHOME/
sudo chown ${username}:${usergid} $KUBEHOME/admin.conf
sudo chmod g+r $KUBEHOME/admin.conf

sudo kubectl create -f $DEPLOY_CONFIG/kube-flannel-rbac.yml
sudo kubectl create -f $DEPLOY_CONFIG/kube-flannel.yml

# use this to enable autocomplete
source <(kubectl completion bash)

# kubectl get nodes --kubeconfig=${KUBEHOME}/admin.conf -s https://155.98.36.111:6443
# Install dashboard: https://github.com/kubernetes/dashboard
#sudo kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/master/src/deploy/recommended/kubernetes-dashboard.yaml
 
# run the proxy to make the dashboard portal accessible from outside
#sudo kubectl proxy  --kubeconfig=${KUBEHOME}/admin.conf  &

# https://github.com/kubernetes/dashboard/wiki/Creating-sample-user
kubectl create -f $DEPLOY_CONFIG/create-cluster-role-binding-admin.yaml  
kubectl create -f $DEPLOY_CONFIG/create-service-account-admin-uesr-dashboard.yaml
# to print the token, use this cmd below to paste into the browser.
# kubectl -n kube-system describe secret $(kubectl -n kube-system get secret | grep admin-user | awk '{print $1}') |grep token: | awk '{print $2}'

# jid for json parsing.
export GOPATH=${WORKINGDIR}/go/gopath
mkdir -p $GOPATH
export PATH=$PATH:$GOPATH/bin
sudo go get -u github.com/simeji/jid/cmd/jid
sudo go build -o /usr/bin/jid github.com/simeji/jid/cmd/jid

# install helm in case we needs it.
##wget https://storage.googleapis.com/kubernetes-helm/helm-v2.9.1-linux-amd64.tar.gz
##tar xf helm-v2.9.1-linux-amd64.tar.gz
##sudo cp linux-amd64/helm /usr/local/bin/helm

#helm init
# https://docs.helm.sh/using_helm/#role-based-access-control
##kubectl create serviceaccount --namespace kube-system tiller
##kubectl create clusterrolebinding tiller-cluster-rule --clusterrole=cluster-admin --serviceaccount=kube-system:tiller
##kubectl patch deploy --namespace kube-system tiller-deploy -p '{"spec":{"template":{"spec":{"serviceAccount":"tiller"}}}}'      
##helm init --service-account tiller --upgrade

#source <(helm completion bash)

# Wait till the slave nodes get joined and update the kubelet daemon successfully

#echo "Waiting for slaves nodes..."
#nodes=(`ssh -o StrictHostKeyChecking=no ${username}@ops.emulab.net "/usr/testbed/bin/node_list -p -e ${projectid},${experimentid};"`)
#node_cnt=${#nodes[@]}
#joined_cnt=$(( `kubectl get nodes |wc -l` - 1 ))
#while [ $node_cnt -ne $joined_cnt ]
#do 
#    joined_cnt=$(( `kubectl get nodes |wc -l` - 1 ))
#    sleep 1
#done

echo "Kubernetes is ready at: http://localhost:8001/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/#!/login"

# optional address
echo "Or, another access option"
echo "kubernetes dashboard endpoint: $dashboard_endpoint"
# dashboard credential
echo "And this is the dashboard credential: $dashboard_credential"

# to know how much time it takes to instantiate everything.
echo "Finishing..."
date

#Rename script file to avoid reinstall on boot
cd /mnt/extra/
mv master.sh master.sh-old
mv slave.sh slave.sh-old
cd

#!/bin/bash -x
################################################################################
#   Copyright (c) 2019 AT&T Intellectual Property.                             #
#   Copyright (c) 2019 Nokia.                                                  #
#                                                                              #
#   Licensed under the Apache License, Version 2.0 (the "License");            #
#   you may not use this file except in compliance with the License.           #
#   You may obtain a copy of the License at                                    #
#                                                                              #
#       http://www.apache.org/licenses/LICENSE-2.0                             #
#                                                                              #
#   Unless required by applicable law or agreed to in writing, software        #
#   distributed under the License is distributed on an "AS IS" BASIS,          #
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   #
#   See the License for the specific language governing permissions and        #
#   limitations under the License.                                             #
################################################################################


# first parameter: number of expected running pods
# second parameter: namespace (all-namespaces means all namespaces)
# third parameter: [optional] keyword
wait_for_pods_running () {
  NS="$2"
  CMD="kubectl get pods --all-namespaces "
  if [ "$NS" != "all-namespaces" ]; then
    CMD="kubectl get pods -n $2 "
  fi
  KEYWORD="Running"
  if [ "$#" == "3" ]; then
    KEYWORD="${3}.*Running"
  fi

  CMD2="$CMD | grep \"$KEYWORD\" | wc -l"
  NUMPODS=$(eval "$CMD2")
  echo "waiting for $NUMPODS/$1 pods running in namespace [$NS] with keyword [$KEYWORD]"
  while [  $NUMPODS -lt $1 ]; do
    sleep 5
    NUMPODS=$(eval "$CMD2")
    echo "> waiting for $NUMPODS/$1 pods running in namespace [$NS] with keyword [$KEYWORD]"
  done 
}


# first parameter: interface name
start_ipv6_if () {
  # enable ipv6 interface
  # standard Ubuntu cloud image does not have dual interface configuration or ipv6
  IPv6IF="$1"
  if ifconfig -a $IPv6IF; then
    echo "" >> /etc/network/interfaces.d/50-cloud-init.cfg
    #echo "auto ${IPv6IF}" >> /etc/network/interfaces.d/50-cloud-init.cfg
    echo "allow-hotplug ${IPv6IF}" >> /etc/network/interfaces.d/50-cloud-init.cfg
    echo "iface ${IPv6IF} inet6 auto" >> /etc/network/interfaces.d/50-cloud-init.cfg
    #dhclient -r $IPv6IF
    #systemctl restart networking
    ifconfig ${IPv6IF} up
  fi
}

echo "k8s_vm_install.sh"
set -x
export DEBIAN_FRONTEND=noninteractive
echo "__host_private_ip_addr__ $(hostname)" >> /etc/hosts
printenv

mkdir -p /opt/config
echo "__docker_version__" > /opt/config/docker_version.txt
echo "__k8s_version__" > /opt/config/k8s_version.txt
echo "__k8s_cni_version__" > /opt/config/k8s_cni_version.txt
echo "__helm_version__" > /opt/config/helm_version.txt
echo "__host_private_ip_addr__" > /opt/config/host_private_ip_addr.txt
echo "__k8s_mst_floating_ip_addr__" > /opt/config/k8s_mst_floating_ip_addr.txt
echo "__k8s_mst_private_ip_addr__" > /opt/config/k8s_mst_private_ip_addr.txt
echo "__mtu__" > /opt/config/mtu.txt
echo "__cinder_volume_id__" > /opt/config/cinder_volume_id.txt
echo "__stack_name__" > /opt/config/stack_name.txt

ISAUX='false'
if [[ $(cat /opt/config/stack_name.txt) == *aux* ]]; then
  ISAUX='true'
fi

modprobe -- ip_vs
modprobe -- ip_vs_rr
modprobe -- ip_vs_wrr
modprobe -- ip_vs_sh
modprobe -- nf_conntrack_ipv4
modprobe -- nf_conntrack_ipv6
modprobe -- nf_conntrack_proto_sctp

start_ipv6_if ens4

# disable swap
SWAPFILES=$(grep swap /etc/fstab | sed '/^#/ d' |cut -f1 -d' ')
if [ ! -z $SWAPFILES ]; then
  for SWAPFILE in $SWAPFILES
  do
    if [ ! -z $SWAPFILE ]; then
      echo "disabling swap file $SWAPFILE"
      if [[ $SWAPFILE == UUID* ]]; then
        UUID=$(echo $SWAPFILE | cut -f2 -d'=')
        swapoff -U $UUID
      else
        swapoff $SWAPFILE
      fi
      # edit /etc/fstab file, remove line with /swapfile
      sed -i -e "/$SWAPFILE/d" /etc/fstab
    fi
  done
fi
# disable swap
#swapoff /swapfile
# edit /etc/fstab file, remove line with /swapfile
#sed -i -e '/swapfile/d' /etc/fstab


DOCKERV=$(cat /opt/config/docker_version.txt)
KUBEV=$(cat /opt/config/k8s_version.txt)
KUBECNIV=$(cat /opt/config/k8s_cni_version.txt)

KUBEVERSION="${KUBEV}-00"
CNIVERSION="${KUBECNIV}-00"
DOCKERVERSION="${DOCKERV}-0ubuntu1.2~16.04.1"
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
echo 'deb http://apt.kubernetes.io/ kubernetes-xenial main' > /etc/apt/sources.list.d/kubernetes.list

# install low latency kernel, docker.io, and kubernetes
apt-get update
apt-get install -y linux-image-4.15.0-45-lowlatency curl jq netcat docker.io=${DOCKERVERSION}
apt-get install -y kubernetes-cni=${CNIVERSION}
apt-get install -y --allow-unauthenticated kubeadm=${KUBEVERSION} kubelet=${KUBEVERSION} kubectl=${KUBEVERSION}
apt-mark hold kubernetes-cni kubelet kubeadm kubectl


# test access to k8s docker registry
kubeadm config images pull


# non-master nodes have hostnames ending with -[0-9][0-9]
if [[ $(hostname) == *-[0-9][0-9] ]]; then
  echo "Done for non-master node"
  echo "Starting an NC TCP server on port 29999 to indicate we are ready"
  nc -l -p 29999 &
else 
  # below are steps for initializating master node, only run on the master node.  
  # minion node join will be triggered from the caller of the stack creation as ssh command.


  # create kubenetes config file
  if [[ ${KUBEV} == 1.13.* ]]; then
    cat <<EOF >/root/config.yaml
apiVersion: kubeadm.k8s.io/v1alpha3
kubernetesVersion: v${KUBEV}
kind: ClusterConfiguration
apiServerExtraArgs:
  feature-gates: SCTPSupport=true
networking:
  dnsDomain: cluster.local
  podSubnet: 10.244.0.0/16
  serviceSubnet: 10.96.0.0/12

---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: ipvs
EOF

  elif [[ ${KUBEV} == 1.14.* ]]; then
    cat <<EOF >/root/config.yaml
apiVersion: kubeadm.k8s.io/v1beta1
kubernetesVersion: v${KUBEV}
kind: ClusterConfiguration
apiServerExtraArgs:
  feature-gates: SCTPSupport=true
networking:
  dnsDomain: cluster.local
  podSubnet: 10.244.0.0/16
  serviceSubnet: 10.96.0.0/12

---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: ipvs
EOF

  else
    echo "Unsupported Kubernetes version requested.  Bail."
    exit
  fi


  # create a RBAC file for helm (tiller)
  cat <<EOF > /root/rbac-config.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: tiller
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: tiller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: tiller
    namespace: kube-system
EOF

  # start cluster (make sure CIDR is enabled with the flag)
  kubeadm init --config /root/config.yaml


  # install Helm
  HELMV=$(cat /opt/config/helm_version.txt)
  HELMVERSION=${HELMV}
  cd /root
  mkdir Helm
  cd Helm
  wget https://storage.googleapis.com/kubernetes-helm/helm-v${HELMVERSION}-linux-amd64.tar.gz
  tar -xvf helm-v${HELMVERSION}-linux-amd64.tar.gz
  mv linux-amd64/helm /usr/local/bin/helm

  # set up kubectl credential and config
  cd /root
  rm -rf .kube
  mkdir -p .kube
  cp -i /etc/kubernetes/admin.conf /root/.kube/config
  chown root:root /root/.kube/config

  # at this point we should be able to use kubectl
  kubectl get pods --all-namespaces

  # install flannel
  kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/bc79dd1505b0c8681ece4de4c0d86c5cd2643275/Documentation/kube-flannel.yml


  # waiting for all 8 kube-system pods to be in running state
  # (at this point, minions have not joined yet)
  wait_for_pods_running 8 kube-system

  # if running a single node cluster, need to enable master node to run pods
  kubectl taint nodes --all node-role.kubernetes.io/master-

  cd /root
  # install RBAC for Helm
  kubectl create -f rbac-config.yaml


  rm -rf /root/.helm
  helm init --service-account tiller
  export HELM_HOME="/root/.helm"

  # waiting for tiller pod to be in running state
  wait_for_pods_running 1 kube-system tiller-deploy

  while ! helm version; do
    echo "Waiting for Helm to be ready"
    sleep 15
  done

  # install ingress controller db-less kong
  helm install stable/kong --set ingressController.enabled=true --set postgresql.enabled=false --set env.database=off


  echo "Starting an NC TCP server on port 29999 to indicate we are ready"
  nc -l -p 29999 &

  echo "Done with master node setup"
fi


# add rancodev CI tool hostnames
if [[ ! -z "${__RUNRICENV_GERRIT_IP__}" && ! -z "${__RUNRICENV_GERRIT_HOST__}" ]]; then 
  echo "${__RUNRICENV_GERRIT_IP__} ${__RUNRICENV_GERRIT_HOST__}" >> /etc/hosts
fi
if [[ ! -z "${__RUNRICENV_DOCKER_IP__}" && ! -z "${__RUNRICENV_DOCKER_HOST__}" ]]; then 
  echo "${__RUNRICENV_DOCKER_IP__} ${__RUNRICENV_DOCKER_HOST__}" >> /etc/hosts
fi
if [[ ! -z "${__RUNRICENV_HELMREPO_IP__}" && ! -z "${__RUNRICENV_HELMREPO_HOST__}" ]]; then 
  echo "${__RUNRICENV_HELMREPO_IP__} ${__RUNRICENV_HELMREPO_HOST__}" >> /etc/hosts
fi

if [ ! -z "${__RUNRICENV_HELMREPO_CERT__}" ]; then
  cat <<EOF >/etc/ca-certificates/update.d/helm.crt
${__RUNRICENV_HELMREPO_CERT__}
EOF
fi

# add cert for accessing docker registry in Azure
if [ ! -z "${__RUNRICENV_DOCKER_CERT__}" ]; then
  mkdir -p /etc/docker/certs.d/${__RUNRICENV_DOCKER_HOST__}:${__RUNRICENV_DOCKER_PORT__}
  cat <<EOF >/etc/docker/ca.crt
${__RUNRICENV_DOCKER_CERT__}
EOF
  cp /etc/docker/ca.crt /etc/docker/certs.d/${__RUNRICENV_DOCKER_HOST__}:${__RUNRICENV_DOCKER_PORT__}/ca.crt

  service docker restart
  systemctl enable docker.service
  docker login -u ${__RUNRICENV_DOCKER_USER__} -p ${__RUNRICENV_DOCKER_PASS__} ${__RUNRICENV_DOCKER_HOST__}:${__RUNRICENV_DOCKER_PORT__}
  docker pull ${__RUNRICENV_DOCKER_HOST__}:${__RUNRICENV_DOCKER_PORT__}/whoami:0.0.1
fi

