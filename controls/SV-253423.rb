control 'SV-253423' do
  title 'The convenience PIN for Windows 11 must be disabled.'
  desc 'This policy controls whether a domain user can sign in using a convenience PIN to prevent enabling (Password Stuffer).'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\System

Value Name: AllowDomainPINLogon
Value Type: REG_DWORD
Value data: 0'
  desc 'fix', 'Disable the convenience PIN sign-in.

To correct this, configure the policy value for Computer Configuration >> Administrative Templates >> System >> Logon >> Set "Turn on convenience PIN sign-in" to "Disabled".'
  impact 0.5
  tag check_id: 'C-56876r829351_chk'
  tag severity: 'medium'
  tag gid: 'V-253423'
  tag rid: 'SV-253423r958478_rule'
  tag stig_id: 'WN11-CC-000370'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56826r840184_fix'
  tag 'documentable'
  tag legacy: ['V-99559', 'SV-108663']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

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
    describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
      it { should have_property 'AllowDomainPINLogon' }
      its('AllowDomainPINLogon') { should cmp 0 }
    end
  end
end
