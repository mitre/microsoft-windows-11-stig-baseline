control 'SV-268318' do
  title 'Windows 11 systems must use either Group Policy or an approved Mobile Device Management (MDM) product to enforce STIG compliance.'
  desc 'Without Windows 11 systems being managed, devices could be rogue and become targets of an attacker.'
  desc 'check', 'Verify the Windows 11 system is receiving policy from either group Policy or an MDM with the following steps:

From a command line or PowerShell:

gpresult /R
OS Configuration: Member Workstation

If the system is not being managed by GPO, ask the administrator to indicate which MDM is managing the device.

If the Window 11 system is not receiving policy from either group Policy or an MDM, this is a finding.'
  desc 'fix', 'Configure the Windows 11 system to use either Group Policy or an approved MDM product to enforce STIG compliance.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-72339r1028267_chk'
  tag severity: 'medium'
  tag gid: 'V-268318'
  tag rid: 'SV-268318r1028268_rule'
  tag stig_id: 'WN11-CC-000063'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-72242r1028259_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe.one do
    describe powershell('gpresult /R | ConvertTo-Json') do
      its('stdout.strip') { should match(/OS Configuration:\s+Member Workstation/) }
    end

    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\OMADM\MDMDeviceID') do
      its('DeviceClientId') { should_not be_empty }
    end
  end
end
