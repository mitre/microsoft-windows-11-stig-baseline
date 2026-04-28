# Local Testing Against a Windows 11 VM

This guide covers running the InSpec profile from a Mac host against a Windows 11
VM (e.g., a UTM VM on Apple Silicon) over WinRM.

> **Scope:** lab/demo setup. The configuration here uses HTTP + Basic auth,
> which is fine for an isolated lab VM but will fail (and rightly so) once the
> STIG baseline is applied to the target. For a hardened target, use HTTPS +
> certificate auth, or test against a snapshot you can roll back.

## 0. Use the right Windows SKU

The DISA Windows 11 STIG targets **Enterprise** edition. Many controls in this
profile reference features that aren't present on Home: BitLocker policy
surface, AppLocker, Credential Guard, Application Guard, Group Policy
(`gpedit.msc`), and most domain controls. Running the profile against **Home**
will produce a flood of failures and N/A results that reflect SKU mismatch
rather than real findings.

Use **Pro at minimum, Enterprise ideally**. CrystalFetch lets you select the
edition during the fetch.

## 1. Enable WinRM on the Windows 11 VM

Open an **elevated PowerShell** session in the VM and run:

```powershell
# Enable WinRM, create the HTTP listener, open the firewall rule
Enable-PSRemoting -Force

# Allow Basic auth + unencrypted HTTP (lab only)
Set-Item WSMan:\localhost\Service\Auth\Basic         -Value $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted   -Value $true
Set-Item WSMan:\localhost\Client\Auth\Basic          -Value $true
Set-Item WSMan:\localhost\Client\AllowUnencrypted    -Value $true

# Confirm the listener is up on 5985
winrm enumerate winrm/config/Listener
```

**Heads-up:** `Enable-PSRemoting` aborts with an error if any active network
adapter is on the **Public** profile — UTM's NAT typically lands there. Either
change the profile to Private (see below) or bypass the check for a lab VM:

```powershell
Enable-PSRemoting -Force -SkipNetworkProfileCheck
```

`Enable-PSRemoting` also only opens the firewall for **Private/Domain**
profiles. If you stay on Public, add an explicit rule:

```powershell
New-NetFirewallRule -DisplayName "WinRM HTTP (lab)" `
  -Direction Inbound -LocalPort 5985 -Protocol TCP `
  -Action Allow -Profile Any
```

Or change the network profile (cleaner, single rule):

```powershell
Get-NetConnectionProfile
Set-NetConnectionProfile -InterfaceAlias "Ethernet" -NetworkCategory Private
```

## 2. Find the VM's IP

In the VM:

```powershell
Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.InterfaceAlias -notmatch 'Loopback' }
```

From the Mac host, the UTM NAT subnet is typically `192.168.64.0/24` (Apple
Virtualization backend) or `192.168.65.0/24` (QEMU NAT) — varies by UTM version
and backend. `arp -a` after a ping from the VM will show it.

## 3. Test connectivity from the Mac

```bash
# Sanity check the listener is reachable
nc -vz <VM_IP> 5985

# Then InSpec
inspec detect -t winrm://Administrator@<VM_IP> --password '<pass>'
inspec exec . -t winrm://Administrator@<VM_IP> --password '<pass>'
```

For repeated runs, drop the password into `~/.config/inspec/config.json` or an
env var rather than passing it on the command line.

## 4. Snapshot before hardening

If you intend to apply the STIG baseline to the same VM, snapshot first.
Several controls in this profile will lock down or break the WinRM config above
once applied (`AllowUnencrypted=false`, Basic auth disabled, HTTPS-only).
Roll back the snapshot to iterate.

UTM supports snapshots when the VM uses the **qcow2** disk format. Check the
VM's drive settings before relying on this.
