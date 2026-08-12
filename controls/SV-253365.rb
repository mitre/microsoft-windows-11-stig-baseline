control 'SV-253365' do
  title 'Connections to non-domain networks when connected to a domain authenticated network must be blocked.'
  desc 'Multiple network connections can provide additional attack vectors to a system and must be limited. When connected to a domain, communication must go through the domain connection.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy\\

Value Name: fBlockNonDomain

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Windows Connection Manager >> "Prohibit connection to non-domain networks when connected to domain authenticated network" to "Enabled".'
  impact 0.5
  tag check_id: 'C-56818r829177_chk'
  tag severity: 'medium'
  tag gid: 'V-253365'
  tag rid: 'SV-253365r991589_rule'
  tag stig_id: 'WN11-CC-000060'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56768r829178_fix'
  tag 'documentable'
  tag legacy: ['V-63585', 'SV-78075']
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
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy') do
      it { should have_property 'fBlockNonDomain' }
      its('fBlockNonDomain') { should cmp 1 }
    end
  end
end
