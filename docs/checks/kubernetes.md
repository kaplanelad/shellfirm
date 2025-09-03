# Kubernetes Checks:

- Detects any namespace deletion - the command deletes everything under the namespace.

* `kubectl delete ns {NAMESPACE}` - This command deletes the namespace and all its residing components, prompting for confirmation.

- `kubectl set image ...` - Updates live resource fields (e.g., image, env). Wrong selectors can roll out unintended changes.

- `kubectl scale ... --replicas=0` - Scales resources down to zero replicas, terminating pods and disrupting traffic.

- `kubectl rollout restart|undo ...` - Manages rollouts; undo or restart replaces running pods and may revert recent changes.
