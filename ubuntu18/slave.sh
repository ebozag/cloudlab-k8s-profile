#!/bin/bash
#set -u
#set -x
# deploy sgx on emulab
K8SVERSION=$1
SCRIPTDIR=$(dirname "$0")
WORKINGDIR='/mnt/extra/'
username=$(id -u)
usergid=$(id -g)

sudo chown ${username}:${usergid} ${WORKINGDIR}/ -R
cd $WORKINGDIR
exec >> ${WORKINGDIR}/deploy.log
exec 2>&1

KUBEHOME="${WORKINGDIR}/kube/"
mkdir -p $KUBEHOME && cd $KUBEHOME
export KUBECONFIG=$KUBEHOME/admin.conf

curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add
sudo apt-add-repository "deb http://apt.kubernetes.io/ kubernetes-xenial main"
echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee -a /etc/apt/sources.list.d/kubernetes.list

cd $WORKINGDIR

sudo apt-get update -y
sudo apt autoremove -y
#sudo apt-get -y install build-essential libffi-dev python python-dev  \
#python-pip automake autoconf libtool indent vim tmux jq

version=$(echo $(echo $K8SVERSION |sed 's/v//')-00)
sudo apt install -y docker.io=18.06.1-0ubuntu1~18.04.1
sudo systemctl start docker
sudo systemctl enable docker
sudo apt-get -y kubernetes-cni=0.6.0-00 golang-go jq
sudo docker version
sudo swapoff -a

sudo apt-get install -qy kubelet=$version kubectl=$version kubeadm=$version

master_token=''
while [ -z $master_token ] 
do
    master_token=`ssh -o StrictHostKeyChecking=no m "export KUBECONFIG='/mnt/extra/kube/admin.conf' &&   kubeadm token list |grep authentication | cut -d' ' -f 1"`;
    sleep 1;
done
sudo kubeadm join m:6443 --token $master_token --discovery-token-unsafe-skip-ca-verification 

# patch the kubelet to force --resolv-conf=''
sudo sed -i 's#Environment="KUBELET_CONFIG_ARGS=--config=/var/lib/kubelet/config.yaml"#Environment="KUBELET_CONFIG_ARGS=--config=/var/lib/kubelet/config.yaml --resolv-conf=''"#g' /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
sudo systemctl daemon-reload 
sudo systemctl restart kubelet.service

# if it complains that "[ERROR Port-10250]: Port 10250 is in use", kill the process.
# if it complains some file already exist, remove those. [ERROR FileAvailable--etc-kubernetes-pki-ca.crt]: /etc/kubernetes/pki/ca.crt already exists

date

#Rename script file to avoid reinstall on boot
cd /mnt/extra/
mv master.sh master.sh-old
mv slave.sh slave.sh-old
cd

