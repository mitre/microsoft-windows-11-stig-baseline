control 'SV-253392' do
  title 'Enhanced diagnostic data must be limited to the minimum required to support Windows Analytics.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Limiting this capability will prevent potentially sensitive information from being sent outside the enterprise. The "Enhanced" level for telemetry includes additional information beyond "Security" and "Basic" on how Windows and apps are used and advanced reliability data. Windows Analytics can use a "limited enhanced" level to provide information such as health data for devices.'
  desc 'check', 'If "Enhanced" level is enabled for telemetry, this must be configured. If "Security" or "Basic" are configured, this is NA. (See WN11-CC-000205).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\\

Value Name: LimitEnhancedDiagnosticDataWindowsAnalytics

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Data Collection and Preview Builds >> "Limit optional diagnostic data for Windows Analytics" to "Enabled" with "Enable Desktop Analytics collection" selected in "Options:".'
  impact 0.5
  tag check_id: 'C-56845r829258_chk'
  tag severity: 'medium'
  tag gid: 'V-253392'
  tag rid: 'SV-253392r991589_rule'
  tag stig_id: 'WN11-CC-000204'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56795r829259_fix'
  tag 'documentable'
  tag legacy: ['SV-96859', 'V-82145']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId >= '1709'
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection') do
      it { should have_property 'LimitEnhancedDiagnosticDataWindowsAnalytics' }
      its('LimitEnhancedDiagnosticDataWindowsAnalytics') { should cmp 1 }
    end
  else
    impact 0.0
    describe 'This setting is applicable starting with v1709 or later of Windows 10; it is NA for prior versions' do
      skip 'This setting is applicable starting with v1709 or later of Windows 10; it is NA for prior versions.'
    end
  end
end
