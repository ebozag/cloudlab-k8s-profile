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
