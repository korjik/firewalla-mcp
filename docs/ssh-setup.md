# Enable SSH and install your public key

The owner performs these steps on a trusted local network. This project does not create keys or change router settings automatically.

## Enable local access in the Firewalla app

In the box's settings (gear), open Advanced → Configurations → SSH Console. Reveal the password through the masked-password control; Firewalla instructs first-time users to reset it first. On Gold/Purple, enable the appropriate local network for SSH. In router mode that is the LAN; Simple Mode labels differ, so use the official mode-specific instructions and never expose the service through your Internet edge. Log in as `pi`, not root. Firewalla says SSH passwords can rotate on reboot and after remote support.

Source: [Firewalla: How to access Firewalla using SSH?](https://help.firewalla.com/hc/en-us/articles/115004397274-How-to-access-Firewalla-using-SSH), checked 2026-10-29. Product UI may change. Do not modify files in the Firewalla source directory.

## Verify the host before supplying a password

Substitute your actual LAN address for this documentation-only example:

```sh
ssh pi@192.0.2.1
```

Before accepting the first host key, compare its SHA256 fingerprint with a value obtained through an independently trusted console, previously verified administrative session, or trusted administrator. From that trusted access path the owner can inspect the public host key fingerprint:

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Do not consider `ssh-keyscan` alone proof of identity: it fetches the key presented on the network. If no trusted comparison is possible, stop and establish one. After verification, retain the accepted key in your dedicated `known_hosts` file. Never set `StrictHostKeyChecking=no`. A changed key needs investigation and fresh verification, not automatic deletion.

## Generate a dedicated client key

Run on the owner-controlled machine or intended MCP host, **not** in a chat, repository, or on the router:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/firewalla_mcp_ed25519 -C firewalla-mcp
chmod 600 ~/.ssh/firewalla_mcp_ed25519
```

Choose a passphrase for interactive use. This initial server disables agents and interactive prompts; unattended use requires an owner-provisioned key file usable without a prompt, protected by host permissions and disk/storage controls. The private key remains on the MCP host. Never upload it to GitHub, paste it into the assistant, or copy an existing personal private key between machines.

## Append the public key, preserving existing keys

After host verification and initial password login work, `ssh-copy-id -i ~/.ssh/firewalla_mcp_ed25519.pub pi@192.0.2.1` appends the public key. Alternatively, append explicitly from the owner machine:

```sh
cat ~/.ssh/firewalla_mcp_ed25519.pub | ssh pi@192.0.2.1 'umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys'
```

Use `>>`, never `>`, for `authorized_keys`. Ensure the existing file ends with a newline before appending, inspect for accidental duplicate keys, and retain existing entries. The `.ssh` directory and file must belong to `pi`; investigate wrong ownership rather than broadly changing unrelated files. Only the `.pub` file is transmitted. Keep the initial session open while testing a second session:

```sh
ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -i ~/.ssh/firewalla_mcp_ed25519 pi@192.0.2.1 true
```

Firewalla staff recommend `ssh-copy-id` in [this support thread](https://help.firewalla.com/hc/en-us/community/posts/360049384313-Static-Route-SSH-key-Authentication). The key generation, append, permission and fingerprint practices here are standard OpenSSH administration, not a claim that Firewalla provides an app key-management feature. Test again after appliance upgrades/reboots; persistence should not be assumed across reset/reimage.

Copy the verified **public host-key entries** into the MCP host's dedicated `known_hosts`, preserving any existing entries. The host/IP and port in configuration must match those entries (`[address]:port` for nondefault ports). Mount the dedicated key and known-hosts files read-only into Docker, with key ownership matching the container UID and key mode 600. Use a separate dedicated key per box where practical.

## Revoke and restrict

To revoke, identify the exact dedicated public-key entry by its key fingerprint/comment, remove only that line from `pi`'s `authorized_keys`, and test that the dedicated key no longer logs in. Do not erase other keys. Delete retired private key material from the MCP host and stop dependent clients. App password rotation does not revoke an SSH public key.

Keep SSH on trusted LANs or an authenticated administrative VPN. Never port-forward it to the public Internet. The `pi` account may have powerful sudo access: application-level read-only tools do not make a stolen key read-only. For stronger enforcement, the reference deployment uses separately reviewed pinned forced-command helpers. See [installation](install.md); ordinary key setup does not install or authorize these automatically. Do not alter sshd, firewall rules or sudo policy just to make a failed diagnostic pass.
