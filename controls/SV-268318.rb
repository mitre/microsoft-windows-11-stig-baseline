control 'SV-268318' do
  title 'Windows 11 systems must use either Group Policy or an approved Mobile Device Management (MDM) product to enforce STIG compliance.'
  desc 'Without Windows 11 systems being managed, devices could be rogue and become targets of an attacker.'
  desc 'check', 'Verify the Windows 11 system is receiving policy from either group Policy or an MDM with the following steps:

From a command line or PowerShell:

gpresult /R
OS Configuration: Member Workstation

If the system OS Configuration is set to "Member Workstation", the system is being managed by GPO.

If the system OS Configuration is set to "Standalone Workstation" and is not being managed by GPO, ask the administrator to indicate which MDM is managing the device.

Issue to the following for Intune. Note: Intune must be running at time of command.

From PowerShell: Get-Service -Name "IntuneManagementExtension"

This should return the following result:

Status = Running, Name = IntuneManagementExtension, DisplayName = Microsoft Intune Management Extension

If Intune is not installed, the response will include "ObjectNotFound" and/or "NoServiceFoundForGivenName".

If the Windows 11 system is not receiving policy from either group Policy or an MDM (that is running), this is a finding.'
  desc 'fix', 'Configure the Windows 11 system to use either Group Policy or an approved MDM product to enforce STIG compliance.'
  impact 0.5
  tag check_id: 'C-72339r1210195_chk'
  tag severity: 'medium'
  tag gid: 'V-268318'
  tag rid: 'SV-268318r1268251_rule'
  tag stig_id: 'WN11-CC-000063'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-72242r1028259_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # Pass if the system receives policy from EITHER Group Policy (Member Workstation) OR an MDM such as Intune
  describe.one do
    describe powershell("(gpresult /R) | Out-String") do
      its('stdout') { should match(/OS Configuration:\s+Member Workstation/i) }
    end

    # Simple MDM presence check via OMA DM provisioning key or Intune service
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Provisioning\\OMADM\\MDMDeviceID') do
      it { should exist }
    end

    describe powershell("(Get-Service -Name 'IntuneManagementExtension' -ErrorAction SilentlyContinue).Status") do
      its('stdout.strip') { should match(/^Running$/) }
    end
  end
end
