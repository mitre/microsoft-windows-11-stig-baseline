control 'SV-253401' do
  title 'Windows 11 must be configured to require a minimum pin length of six characters or greater.'
  desc 'Windows allows the use of PINs as well as biometrics for authentication without sending a password to a network or website where it could be compromised.  Longer minimum PIN lengths increase the available combinations an attacker would have to attempt.  Shorter minimum length significantly reduces the strength.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\PassportForWork\\PINComplexity\\

Value Name: MinimumPINLength

Type: REG_DWORD
Value: 6 (or greater)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> PIN Complexity >> "Minimum PIN length" to "6" or greater.'
  impact 0.5
  tag check_id: 'C-56854r829285_chk'
  tag severity: 'medium'
  tag gid: 'V-253401'
  tag rid: 'SV-253401r991589_rule'
  tag stig_id: 'WN11-CC-000260'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56804r829286_fix'
  tag 'documentable'
  tag legacy: ['SV-78211', 'V-63721']
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

  #Per MSFT Docs, Windows Hello for Business is only availible on EntraID, Domain, or FIDO IDP credentials
  if join_type == 'None'
    impact 0.0
    describe 'This system is not joined to EntraID or a domain, therefore this control is Not Applicable' do
      skip 'This system is not joined to EntraID or a domain, therefore this control is Not Applicable'
    end

  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity') do
    it { should have_property 'MinimumPINLength' }
    its('MinimumPINLength') { should be >= 6 }
    end
  end
end