control 'SV-253425' do
  title 'Windows 11 must be configured to prevent users from receiving suggestions for third-party or additional applications.'
  desc 'Windows spotlight features may suggest apps and content from third-party software publishers in addition to Microsoft apps and content.'
  desc 'check', %q(Note: This Check must be performed for each interactive user profile on the system.
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\CloudContent\

Value Name: DisableThirdPartySuggestions

Type: REG_DWORD
Value: 0x00000001 (1)

Note: This requirement is applicable to profiles for interactive logins. It is not applicable for Service accounts.

To determine the system's enabled user profiles:
Run "PowerShell" as an administrator.

Execute the following command:
Get-LocalUser | Where-Object {$_.Enabled -eq $true})
  desc 'fix', 'For each user profile on the system, configure the policy value for User Configuration >> Administrative Templates. >> Windows Components >> Cloud Content >> "Do not suggest third-party content in Windows spotlight" to "Enabled".'
  impact 0.3
  tag check_id: 'C-56878r1259995_chk'
  tag severity: 'low'
  tag gid: 'V-253425'
  tag rid: 'SV-253425r1259997_rule'
  tag stig_id: 'WN11-CC-000390'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56828r1259996_fix'
  tag 'documentable'
  tag legacy: ['V-99563', 'SV-108667']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # HKEY_CURRENT_USER setting, evaluated for each interactive user profile (see libraries/user_registry_helper.rb)
  profiles = user_registry_values('SOFTWARE\Policies\Microsoft\Windows\CloudContent', 'DisableThirdPartySuggestions')

  if profiles.empty?
    impact 0.0
    describe 'No interactive user profiles were found; This System is N/A for Control SV-253425' do
      skip 'No interactive user profiles were found; This System is N/A for Control SV-253425'
    end
  else
    profiles.each do |profile|
      describe "Registry hive for user profile #{profile['Path']} (#{profile['SID']})" do
        subject { profile['Error'] }
        it { should be_nil }
      end
      describe "DisableThirdPartySuggestions for user profile #{profile['Path']} (#{profile['SID']})" do
        subject { profile['Value'] }
        it { should cmp 1 }
      end
    end
  end
end
