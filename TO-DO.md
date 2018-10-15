## Fix the need to copy keys to instances
The profile script requires all nodes (master and slaves) to connect via SSH to other nodes, therefore SSH keys need to be copied into each of the nodes.

## Fix the kubectl configuration
After the cluster is up, it needs to be configured the kubectl tool:

```
username=$(id -nu)
usergid=$(id -ng)
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown ${username}:${usergid} $HOME/.kube/config
kubectl get nodes
```
## Create a new profile with a different machine type
Machine type (pc3000) is currently hard-coded in the profile. You can use a different machine type by modifying the porfile or by cloning it and changing the following lines in the geni-lib script:

```
#kube_m.hardware_type = 'd430'
kube_m.hardware_type = 'pc3000'
#kube_s.hardware_type = 'd430'
kube_s.hardware_type = 'pc3000'
```
