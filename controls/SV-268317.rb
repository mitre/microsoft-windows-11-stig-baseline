control 'SV-268317' do
  title 'Copilot must be disabled for Windows 11.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.'
  desc 'check', 'Run the following PowerShell command as an administrator:

Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*Copilot*" }

If Microsoft.Copilot displays, this is a finding.'
  desc 'fix', 'Open PowerShell as an administrator. Run the following command:

Get-AppxPackage -AllUsers *CoPilot* | Remove-AppxPackage -AllUsers'
  impact 0.5
  tag check_id: 'C-72338r1135318_chk'
  tag severity: 'medium'
  tag gid: 'V-268317'
  tag rid: 'SV-268317r1135320_rule'
  tag stig_id: 'WN11-00-000125'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-72241r1135319_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  describe powershell('Get-AppxPackage -AllUsers -Name "*Copilot*" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name') do
    its('stdout.strip') { should eq '' }
  end
end
