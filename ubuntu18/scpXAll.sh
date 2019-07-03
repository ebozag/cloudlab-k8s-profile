#!/bin/bash
for node in $(kubectl get nodes|grep ^s|cut -d\  -f1)
do 
    echo "#### Node $node ..."
    scp -o StrictHostKeyChecking=no eboza@$node:"$@" .
done
