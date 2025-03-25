# Network Checks

This document provides an overview of the network checks implemented in the `shellfirm` project. Each check is designed to prevent potentially harmful network operations.

- `iptables -F` - This command flushes all firewall rules and prompts for confirmation.

- `iptables -X` - This command deletes all custom chains and prompts for confirmation.

- `iptables -t nat -F` - This command flushes all NAT rules and prompts for confirmation.

- `ufw disable` - This command disables the firewall and prompts for confirmation.

- `ufw --force reset` - This command forcefully resets firewall rules and prompts for confirmation.

- `systemctl stop networking` - This command stops the network service and prompts for confirmation.

- `systemctl stop NetworkManager` - This command stops the NetworkManager service and prompts for confirmation.

- `ifconfig ethX down` - This command brings down the network interface and prompts for confirmation.

- `ip link set ethX down` - This command brings down the network interface using the ip command and prompts for confirmation.

- `route del default` - This command deletes the default route and prompts for confirmation.
