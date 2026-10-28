control 'SV-253370' do
  title 'Credential Guard must be running on Windows 11 systems.'
  desc 'Credential Guard uses virtualization-based security to protect information that could be used in credential theft attacks if compromised. This authentication information, which was stored in the Local Security Authority (LSA) in previous versions of Windows, is isolated from the rest of operating system and can only be accessed by privileged system software.'
  desc 'check', 'Confirm Credential Guard is running.

Run "PowerShell" with elevated privileges (run as administrator).

Enter the following:

"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard"

If "SecurityServicesRunning" does not include a value of "1" (e.g., "{1, 2}"), this is a finding.

Alternately:

Run "System Information".

Under "System Summary", verify the following:

If "virtualization-based Services Running" does not list "Credential Guard", this is a finding.

The policy settings referenced in the Fix section will configure the following registry value. However, due to hardware requirements, the registry value alone does not ensure proper function.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard\\

Value Name: LsaCfgFlags
Value Type: REG_DWORD
Value: 0x00000001 (1) (Enabled with UEFI lock)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Device Guard >> "Turn On virtualization-based Security" to "Enabled" with "Enabled with UEFI lock" selected for "Credential Guard Configuration:".

A Microsoft TechNet article on Credential Guard, including system requirement details, can be found at the following link:

https://docs.microsoft.com/en-us/windows/access-protection/credential-guard/credential-guard'
  impact 0.7
  tag check_id: 'C-56823r1210200_chk'
  tag severity: 'high'
  tag gid: 'V-253370'
  tag rid: 'SV-253370r1268251_rule'
  tag stig_id: 'WN11-CC-000075'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56773r1210201_fix'
  tag 'documentable'
  tag legacy: ['SV-78089', 'V-63599']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  script = json(content: powershell('Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | ConvertTo-Json').stdout.strip).params

  # SecurityServicesRunning value 1 = Credential Guard is running
  describe 'VBS SecurityServicesRunning' do
    subject { Array(script['SecurityServicesRunning']) }
    it { should include 1 }
  end
end
