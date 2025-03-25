# Kubernetes Checks:

- Detects any namespace deletion - the command deletes everything under the namespace.

* `kubectl delete ns {NAMESPACE}` - This command deletes the namespace and all its residing components, prompting for confirmation.
