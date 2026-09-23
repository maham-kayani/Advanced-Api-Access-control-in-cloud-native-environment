#!/bin/sh
# Run from the client-side pod to check the controlled environment.
CLIENT=$(kubectl get pod -n controlled -l app=client-side -o jsonpath='{.items[0].metadata.name}')

kubectl exec -n controlled "$CLIENT" -c client -- curl -s http://server-side/          # expected: 200
kubectl exec -n controlled "$CLIENT" -c client -- curl -s http://server-side/dataset1  # expected: 200
kubectl exec -n controlled "$CLIENT" -c client -- curl -s http://server-side/dataset2  # expected: 403 RBAC: access denied
