# Kubernetes-Strict Checks:

:warning: Make sure that the `kubernetes` group is also enabled :warning:

- `kubectl delete {RESOURCE}` - This command will delete a given resource and prompts for confirmation.

- `kubectl set {RESOURCE}` - This command will update the given resource and prompts for confirmation.

- `kubectl scale {RESOURCE}` - This command will set a new size for a given resource and prompts for confirmation.

- `kubectl rollout {ACTION} {RESOURCE}` - This command will manage a rollout for a given resource and prompts for confirmation.
