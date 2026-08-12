control 'SV-279688' do
  title 'Windows 11 systems must block consumer account user authentication.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore, may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

The Copilot Rewrite functionality within Notepad and Image Generation within Paint is dependent upon the use of AI credits from a Microsoft 365 Personal or Family subscription. Organizational users must not use personal accounts to login to applications on enterprise machines.'
  desc 'check', 'Verify the "block all consumer Microsoft account user authentication" is enabled.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\MicrosoftAccount

Value Name: DisableUserAuth

Value Type: REG_DWORD
Value: 0x00000001 (1)

If the registry value is not "1", this is a finding.'
  desc 'fix', 'Configure the following Group Policy:
Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Account "block all consumer Microsoft account user authentication" to "Enabled".

For systems managed by Intune, apply the DOD Windows 11 STIG Settings Catalog (or equivalent Intune policy) found in the Intune policy package available on cyber.mil.
Steps to create an Intune policy:
1. Sign in to the Intune admin center >> Devices >> Configuration >> Create >> New Policy.
2. Platform: Windows 10 and later. Profile type: Settings Catalog, then click "Create".
3. Basics: Provide a Name and Description of the profile, then click "Next".
4. Configuration settings: Click "+ Add settings" and search for consumer under the Settings picker. Under the Administrative Templates\\Windows Components\\Microsoft account category, check the box next to "Block all consumer Microsoft account user authentication". Click the Enabled radio button, then click "Next".
5. Scope tags: (optional), then click "Next".
6. Assignments: Assign the policy to Entra security groups that contain the target users or devices, then click "Next".
7. Review + create: Review the deployment summary, then click "Create".'
  impact 0.5
  tag check_id: 'C-84241r1153426_chk'
  tag severity: 'medium'
  tag gid: 'V-279688'
  tag rid: 'SV-279688r1153564_rule'
  tag stig_id: 'WN11-00-000126'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-84146r1153427_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MicrosoftAccount') do
    its('DisableUserAuth') { should cmp 1 }
  end
end
