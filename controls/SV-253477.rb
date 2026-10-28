control 'SV-253477' do
  title 'Toast notifications to the lock screen must be turned off.'
  desc 'Toast notifications that are displayed on the lock screen could display sensitive information to unauthorized personnel.  Turning off this feature will limit access to the information to a logged on user.'
  desc 'check', %q(Note: This Check must be performed for each interactive user profile on the system.
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\

Value Name: NoToastApplicationNotificationOnLockScreen

Value Type: REG_DWORD
Value: 1

Note: This requirement is applicable to profiles for interactive logins. It is not applicable for Service accounts.

To determine the system's enabled user profiles:
Run "PowerShell" as an administrator.

Execute the following command:
Get-LocalUser | Where-Object {$_.Enabled -eq $true})
  desc 'fix', 'For each user profile on the system, configure the policy value for User Configuration >> Administrative Templates >> Start Menu and Taskbar >> Notifications >> "Turn off toast notifications on the lock screen" to "Enabled".'
  impact 0.3
  tag check_id: 'C-56930r1260002_chk'
  tag severity: 'low'
  tag gid: 'V-253477'
  tag rid: 'SV-253477r1260004_rule'
  tag stig_id: 'WN11-UC-000015'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56880r1260003_fix'
  tag 'documentable'
  tag legacy: ['V-63839', 'SV-78329']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # HKEY_CURRENT_USER setting, evaluated for each interactive user profile (see libraries/user_registry_helper.rb)
  profiles = user_registry_values('SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications', 'NoToastApplicationNotificationOnLockScreen')

  if profiles.empty?
    impact 0.0
    describe 'No interactive user profiles were found; This System is N/A for Control SV-253477' do
      skip 'No interactive user profiles were found; This System is N/A for Control SV-253477'
    end
  else
    profiles.each do |profile|
      describe "Registry hive for user profile #{profile['Path']} (#{profile['SID']})" do
        subject { profile['Error'] }
        it { should be_nil }
      end
      describe "NoToastApplicationNotificationOnLockScreen for user profile #{profile['Path']} (#{profile['SID']})" do
        subject { profile['Value'] }
        it { should cmp 1 }
      end
    end
  end
end
