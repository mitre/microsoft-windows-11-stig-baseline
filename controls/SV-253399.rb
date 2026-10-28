control 'SV-253399' do
  title 'Windows 11 must be configured to disable Windows Game Recording and Broadcasting.'
  desc 'Windows Game Recording and Broadcasting is intended for use with games; however, it could record screenshots of other applications and expose sensitive data. Disabling the feature will prevent this from occurring.

Note: A different registry location is needed when systems are managed by Intune versus GPO.'
  desc 'check', 'This is NA for Windows 11 LTSC. 
                
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR\\  (For GPO-managed systems)
Or
Registry Path: \\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\ApplicationManagement  (For Intune-managed systems)

Value Name: AllowGameDVR

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'For GPO-managed systems:
Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Game Recording and Broadcasting >> "Enables or disables Windows Game Recording and Broadcasting" to "Disabled".

For Intune-managed systems:
Revise the Intune policy to disable Windows Game Recording and Broadcasting.'
  impact 0.5
  tag check_id: 'C-56852r1259987_chk'
  tag severity: 'medium'
  tag gid: 'V-253399'
  tag rid: 'SV-253399r1259989_rule'
  tag stig_id: 'WN11-CC-000252'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56802r1259988_fix'
  tag 'documentable'
  tag legacy: ['SV-89091', 'V-74417']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  caption = json(command: 'Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption | ConvertTo-Json').params['Caption'].to_s

  if caption =~ /LTSC/i
    impact 0.0
    describe "This is a Windows 11 LTSC system (#{caption}); This System is N/A for Control SV-253399" do
      skip "This is a Windows 11 LTSC system (#{caption}); This System is N/A for Control SV-253399"
    end
  else
    # GPO-managed systems use the GameDVR policy key; Intune-managed systems use the ApplicationManagement CSP
    describe.one do
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR') do
        it { should have_property 'AllowGameDVR' }
        its('AllowGameDVR') { should cmp 0 }
      end
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\ApplicationManagement') do
        it { should have_property 'AllowGameDVR' }
        its('AllowGameDVR') { should cmp 0 }
      end
    end
  end
end
