# Terraform Checks:

- Detect when auto approving a Terraform plan.

- Detect when auto approving replacing a provider in a Terraform state.

- Detect when force deleting a workspace.

- Detect when deleting a workspace without a state lock.

- Detect when force unlocking a state.

* `terraform apply -auto-approve` - This command applies the state without asking for confirmation and prompts for confirmation.

* `terraform state mv/replace-provider` - This command moves or replaces a provider in the state without asking for confirmation and prompts for confirmation.

* `terraform workspace delete -force` - This command deletes a Terraform workspace without asking for confirmation and prompts for confirmation.

* `terraform workspace delete -lock=false` - This command deletes a Terraform workspace without a state lock and prompts for confirmation.

* `terraform force-unlock -force` - This command manually unlocks the state for the defined configuration without asking for confirmation and prompts for confirmation.

- `terraform state mv/replace-provider` with `-dry-run` is excluded from detection.
