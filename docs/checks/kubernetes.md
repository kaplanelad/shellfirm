# Kubernetes Checks:

* `kubectl delete ns` - This deletes everything under the namespace!. The check is regex and will trigger on multiple combination like `k delete ns` / `kubectl -n delete` and any delete combination.