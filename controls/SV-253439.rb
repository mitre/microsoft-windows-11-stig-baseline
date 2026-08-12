control 'SV-253439' do
  title 'Outgoing secure channel traffic must be encrypted.'
  desc 'Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but not all information is encrypted. If this policy is enabled, outgoing secure channel traffic will be encrypted.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: SealSecureChannel

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Domain member: Digitally encrypt secure channel data (when possible)" to "Enabled".'
  impact 0.5
  tag check_id: 'C-56892r829399_chk'
  tag severity: 'medium'
  tag gid: 'V-253439'
  tag rid: 'SV-253439r958908_rule'
  tag stig_id: 'WN11-SO-000040'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-56842r829400_fix'
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']

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
    describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters') do
      it { should have_property 'SealSecureChannel' }
      its('SealSecureChannel') { should cmp 1 }
    end
  end
end
