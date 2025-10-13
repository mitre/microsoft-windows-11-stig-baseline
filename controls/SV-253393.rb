control 'SV-253393' do
  title 'Windows Telemetry must not be configured to Full.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Limiting this capability will prevent potentially sensitive information from being sent outside the enterprise. The "Security" option for Telemetry configures the lowest amount of data, effectively none outside of the Malicious Software Removal Tool (MSRT), Defender and telemetry client settings. "Basic" sends basic diagnostic and usage data and may be required to support some Microsoft services. "Enhanced" includes additional information on how Windows and apps are used and advanced reliability data. Windows Analytics can use a "limited enhanced" level to provide information such as health data for devices.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\\

Value Name: AllowTelemetry

Type: REG_DWORD
Value: 0x00000000 (0) (Security)
0x00000001 (1) (Basic)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Data Collection and Preview Builds >> "Allow Diagnostic Data" to "Enabled" with "Send required diagnostic data" selected in "Options:".'
  impact 0.5
  tag check_id: 'C-56846r829261_chk'
  tag severity: 'medium'
  tag gid: 'V-253393'
  tag rid: 'SV-253393r958564_rule'
  tag stig_id: 'WN11-CC-000205'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag fix_id: 'F-56796r829262_fix'
  tag 'documentable'
  tag legacy: ['V-63683', 'SV-78173']
  tag cci: ['CCI-000366', 'CCI-001312']
  tag nist: ['CM-6 b', 'SI-11 a']

  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection') do
      it { should have_property 'AllowTelemetry' }
      its('AllowTelemetry') { should cmp 0 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection') do
      it { should have_property 'AllowTelemetry' }
      its('AllowTelemetry') { should cmp 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection') do
      it { should have_property 'AllowTelemetry' }
      its('AllowTelemetry') { should cmp 2 }
    end
  end
end
