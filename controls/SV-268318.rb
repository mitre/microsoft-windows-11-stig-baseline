control 'SV-268318' do
  title 'Windows 11 systems must use either Group Policy or an approved Mobile Device Management (MDM) product to enforce STIG compliance.'
  desc 'Without Windows 11 systems being managed, devices could be rogue and become targets of an attacker.'
  desc 'check', 'Verify the Windows 11 system is receiving policy from either group Policy or an MDM with the following steps:

From a command line or PowerShell:

gpresult /R
OS Configuration: Member Workstation

If the system is not being managed by GPO, ask the administrator to indicate which MDM is managing the device.

From PowerShell: Get-Service -Name "IntuneManagementExtension"

If the Windows 11 system is not receiving policy from either group Policy or an MDM, this is a finding.

This is NA for standalone, nondomain-joined systems.'
  desc 'fix', 'Configure the Windows 11 system to use either Group Policy or an approved MDM product to enforce STIG compliance.'
  impact 0.5
  tag check_id: 'C-72339r1135321_chk'
  tag severity: 'medium'
  tag gid: 'V-268318'
  tag rid: 'SV-268318r1135322_rule'
  tag stig_id: 'WN11-CC-000063'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-72242r1028259_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

 join_type = inspec.powershell(<<~EOH).stdout.strip
    $dsreg = & "$env:windir\\system32\\dsregcmd.exe" /status 2>$null
    $azure = ($dsreg | Select-String -Pattern '^\\s*AzureAdJoined\\s*:\\s*').ToString().Split(':')[-1].Trim()
    $domain = ($dsreg | Select-String -Pattern '^\\s*DomainJoined\\s*:\\s*').ToString().Split(':')[-1].Trim()

    if ($azure -eq 'YES' -and $domain -eq 'YES') { 'Hybrid' }
    elseif ($azure -eq 'YES') { 'AzureAD' }
    elseif ($domain -eq 'YES') { 'Domain' }
    else { 'None' }
    EOH

  if join_type == 'None'
    impact 0.0
    describe 'The system is not a member of a domain' do
      skip 'Control is Not Applicable for standalone/Azure AD-only systems.'
    end
  else
    # Domain-joined: pass if EITHER GPO (Member Workstation) OR Intune MDM is present
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
end