control 'SV-253442' do
  title 'The maximum age for machine account passwords must be configured to 30 days or less.'
  desc 'Computer account passwords are changed automatically on a regular basis.  This setting controls the maximum password age that a machine account may have.  This setting must be set to no more than 30 days, ensuring the machine changes its password monthly.'
  desc 'check', '(remove)This is the default configuration for this setting (30 days).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: MaximumPasswordAge

Value Type: REG_DWORD
Value: 0x0000001e (30) (or less, excluding 0)'
  desc 'fix', 'This is the default configuration for this setting (30 days).

Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Domain member: Maximum machine account password age" to "30" or less (excluding 0 which is unacceptable).'
  impact 0.3
  tag check_id: 'C-56895r829408_chk'
  tag severity: 'low'
  tag gid: 'V-253442'
  tag rid: 'SV-253442r991589_rule'
  tag stig_id: 'WN11-SO-000055'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56845r829409_fix'
  tag 'documentable'
  tag legacy: ['SV-78151', 'V-63661']
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
    describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters') do
      it { should have_property 'MaximumPasswordAge' }
      its('MaximumPasswordAge') { should be <= 30 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters') do
      its('MaximumPasswordAge') { should be_positive }
    end
  end
end
