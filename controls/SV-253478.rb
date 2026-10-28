control 'SV-253478' do
  title 'Zone information must be preserved when saving attachments.'
  desc 'Preserving zone of origin (internet, intranet, local, restricted) information on file attachments allows Windows to determine risk.'
  desc 'check', %q(Note: This Check must be performed for each interactive user profile on the system.

The default behavior is for Windows to mark file attachments with their zone information.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_CURRENT_USER
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\

Value Name: SaveZoneInformation

Value Type: REG_DWORD
Value: 0x00000002 (2) (or if the Value Name does not exist)

Note: This requirement is applicable to profiles for interactive logins. It is not applicable for Service accounts.

To determine the system's enabled user profiles:
Run "PowerShell" as an administrator.

Execute the following command:
Get-LocalUser | Where-Object {$_.Enabled -eq $true})
  desc 'fix', 'The default behavior is for Windows to mark file attachments with their zone information.

To correct this, (for each user profile on the system) configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> Attachment Manager >> "Do not preserve zone information in file attachments" to "Not Configured" or "Disabled".'
  impact 0.5
  tag check_id: 'C-56931r1260005_chk'
  tag severity: 'medium'
  tag gid: 'V-253478'
  tag rid: 'SV-253478r1268251_rule'
  tag stig_id: 'WN11-UC-000020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56881r1260006_fix'
  tag 'documentable'
  tag legacy: ['V-63841', 'SV-78331']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # HKEY_CURRENT_USER setting, evaluated for each interactive user profile (see libraries/user_registry_helper.rb)
  profiles = user_registry_values('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments', 'SaveZoneInformation')

  if profiles.empty?
    impact 0.0
    describe 'No interactive user profiles were found; This System is N/A for Control SV-253478' do
      skip 'No interactive user profiles were found; This System is N/A for Control SV-253478'
    end
  else
    profiles.each do |profile|
      describe "Registry hive for user profile #{profile['Path']} (#{profile['SID']})" do
        subject { profile['Error'] }
        it { should be_nil }
      end
      # A value of 2, or the value not existing, is compliant; 1 is a finding
      describe "SaveZoneInformation for user profile #{profile['Path']} (#{profile['SID']})" do
        subject { profile['Value'] }
        it { should_not cmp 1 }
      end
    end
  end
end
