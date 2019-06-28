#!/bin/bash
# Requires 2 parameter: master node
if [ "$#" -lt 2 ]; then
    echo "Illegal number of parameters, must include 2 parameters: master node hostname, and the number of slave nodes"
    exit 1
fi
masternode="$1"
nodes="$2"
hostnames="$(eval echo "s{1..$nodes} ")"

echo "### Configure kubectl..."
echo "Configuring kubectl at m.k8sc$clusterId.espol-sched.emulab.net..."
ssh -o "StrictHostKeyChecking=no"  ${masternode} /bin/bash << EOF
mkdir -p .kube
sudo cp -i /etc/kubernetes/admin.conf .kube/config
sudo chown eboza:ESPOL-sched .kube/config
kubectl get nodes
EOF


echo "Copying kubectl configuration from master node..."
mkdir -p ~/.kube/.kube
scp -o StrictHostKeyChecking=no ${masternode}:/users/eboza/.kube/config ~/.kube/config
kubectl get nodes

echo "Get the join command from master node..."
JOINCMD=$(ssh $masternode -q -o "StrictHostKeyChecking no" sudo kubeadm token create --print-join-command)

clusterdomain=$(kubectl get nodes|grep ^m|cut -d\  -f1|cut -c 3-)
# Join each of the slaves nodes
for hostname in $hostnames
do
    echo "Preparing node: ${hostname}.${clusterdomain}..." 
    ssh -o "StrictHostKeyChecking=no" ${hostname}.${clusterdomain} sudo $JOINCMD
done

echo "Waiting for nodes to join..."
while [ $(kubectl get nodes|grep -c NotReady) -gt 0 ]
do
    echo "Waiting for $(kubectl get nodes|grep -c NotReady) node(s) to join..."
    sleep 5
done
echo "All nodes has been restarted: "
kubectl get nodes

echo "Initialization finished."
exit 0
