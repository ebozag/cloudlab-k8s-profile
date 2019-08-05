#!/bin/bash
################################################################################
#   Copyright (c) 2019 AT&T Intellectual Property.                             #
#   Copyright (c) 2019 Nokia.                                                  #
#   Copyright (c) 2019 Escuela Superior Politecnica del Litoral - ESPOL.       #
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

### Show K8s requested version
echo "K8s requested version = $1"

echo "Current user: $(whoami)"
echo "Current directory: $(pwd)"


KUBEHOME="${WORKINGDIR}/.kube/"
DEPLOY_CONFIG="${WORKINGDIR}/cloudlab-k8s-profile/$K8SVERSION/kube-deploy-yaml/"
mkdir -p $KUBEHOME && cd $KUBEHOME
export KUBECONFIG=$KUBEHOME/config

cd $WORKINGDIR

### Commands from RIC infra install
### ric-infra/00-Kubernetes/etc/infra.rc
# modify below for RIC infrastructure (docker-k8s-helm) component versions
INFRA_DOCKER_VERSION="18.06.1"
INFRA_K8S_VERSION="1.13.3"
INFRA_CNI_VERSION="0.6.0"
INFRA_HELM_VERSION="2.12.3"

#### This is how I used to install K8s packages using the version received by the script.

##version=$(echo $(echo $K8SVERSION |sed 's/v//')-00)
##sudo apt-get install -y kubernetes-cni=0.6.0-00 golang-go jq 
##sudo apt-get install -qy kubelet=$version kubectl=$version kubeadm=$version
##sudo kubeadm init --pod-network-cidr=192.168.0.0/16 --kubernetes-version="$K8SVERSION" --ignore-preflight-errors='KubeletVersion'

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
#SWAPFILES=$(grep swap /etc/fstab | sed '/^#/ d' |cut -f1 -d' ')
SWAPFILES=$(grep swap /etc/fstab | sed '/^#/ d' |cut -f1 )
if [ ! -z $SWAPFILES ]; then
  for SWAPFILE in $SWAPFILES
  do
    if [ ! -z $SWAPFILE ]; then
      echo "disabling swap file $SWAPFILE"
      if [[ $SWAPFILE == UUID* ]]; then
        UUID=$(echo $SWAPFILE | cut -f2 -d'=')
        sudo swapoff -U $UUID
      else
        sudo swapoff $SWAPFILE
      fi
      # edit /etc/fstab file, remove line with /swapfile
      sudo sed -i -e "/$SWAPFILE/d" /etc/fstab
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
sudo apt-get install -y curl jq netcat 
### Install docker, and change the default folder from /usr/lib/docker to /mnt/extra/docker

##TO-DO: fix the docker version
####sudo apt-get install -y docker.io=${DOCKERVERSION}
sudo apt-get install -y docker.io

sudo mkdir /mnt/extra/docker
sudo chown root:root /mnt/extra/docker
sudo chmod 711 /mnt/extra/docker
sudo sed -i 's/\-H fd/\-g \/mnt\/extra\/docker \-H fd/g' /lib/systemd/system/docker.service

### Install Kubernetes
sudo apt-get install -y kubernetes-cni=${CNIVERSION}
sudo apt-get install -y --allow-unauthenticated kubeadm=${KUBEVERSION} kubelet=${KUBEVERSION} kubectl=${KUBEVERSION}
sudo apt-mark hold kubernetes-cni kubelet kubeadm kubectl

### Disable AppArmor, as it doesn't allow to create MariaDB container. 
### See Troubleshooting section on https://mariadb.com/kb/en/library/installing-and-using-mariadb-via-docker/
sudo apt-get purge -y --auto-remove apparmor

# Load kernel modules 
sudo modprobe -- ip_vs
sudo modprobe -- ip_vs_rr
sudo modprobe -- ip_vs_wrr
sudo modprobe -- ip_vs_sh
sudo modprobe -- nf_conntrack_ipv4
sudo modprobe -- nf_conntrack_ipv6
sudo modprobe -- nf_conntrack_proto_sctp    ### Probably will give an error, as recent versions include this as part of the Kernel.

# Restart docker and configure to start at boot
sudo service docker restart
sudo systemctl enable docker.service

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
  sudo kubeadm init --config "${WORKINGDIR}/config.yaml"

  # install Helm
  HELMV=${INFRA_HELM_VERSION}
  HELMVERSION=${HELMV}
  cd "${WORKINGDIR}"
  mkdir Helm
  cd Helm
  wget https://storage.googleapis.com/kubernetes-helm/helm-v${HELMVERSION}-linux-amd64.tar.gz
  tar -xvf helm-v${HELMVERSION}-linux-amd64.tar.gz
  sudo mv linux-amd64/helm /usr/local/bin/helm

  # set up kubectl credential and config
  sudo cp /etc/kubernetes/admin.conf $KUBEHOME/config
  sudo chown ${username}:${usergid} $KUBEHOME/config
  sudo chmod g+r $KUBEHOME/config

  # at this point we should be able to use kubectl
  kubectl get pods --all-namespaces

  # install flannel
  kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/bc79dd1505b0c8681ece4de4c0d86c5cd2643275/Documentation/kube-flannel.yml


  # waiting for all 8 kube-system pods to be in running state
  # (at this point, minions have not joined yet)
###  wait_for_pods_running 8 kube-system

  # if running a single node cluster, need to enable master node to run pods
  kubectl taint nodes --all node-role.kubernetes.io/master-

  cd "${WORKINGDIR}"
  # install RBAC for Helm
  kubectl create -f rbac-config.yaml


  rm -rf "${WORKINGDIR}/.helm"
  helm init --service-account tiller
  export HELM_HOME="${WORKINGDIR}/.helm"

  # waiting for tiller pod to be in running state
###  wait_for_pods_running 1 kube-system tiller-deploy

  while ! helm version; do
    echo "Waiting for Helm to be ready"
    sleep 15
  done

  # install ingress controller db-less kong
  ## helm install stable/kong --set ingressController.enabled=true --set postgresql.enabled=false --set env.database=off


  echo "Starting an NC TCP server on port 29999 to indicate we are ready"
  nc -l -p 29999 &

  echo "Done with master node setup"
fi

echo "FINISHED part copied from RIC"

#Rename script file to avoid reinstall on boot
echo "Rename script file to avoid reinstall on boot..."
cd /mnt/extra/
mv install-k8s-4ric-cloudlab.sh install-k8s-4ric-cloudlab.sh-old
mv master.sh master.sh-old
mv slave.sh slave.sh-old

echo "FINISHED!"

exit 0
###############
###############
###############
###############

