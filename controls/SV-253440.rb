control 'SV-253440' do
  title 'Outgoing secure channel traffic must be signed.'
  desc 'Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but the channel is not integrity checked.  If this policy is enabled, outgoing secure channel traffic will be signed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: SignSecureChannel

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Domain member: Digitally sign secure channel data (when possible)" to "Enabled".'
  impact 0.5
  tag check_id: 'C-56893r829402_chk'
  tag severity: 'medium'
  tag gid: 'V-253440'
  tag rid: 'SV-253440r958908_rule'
  tag stig_id: 'WN11-SO-000045'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-56843r829403_fix'
  tag 'documentable'
  tag legacy: ['SV-78137', 'V-63647']
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters') do
    it { should have_property 'SignSecureChannel' }
    its('SignSecureChannel') { should cmp 1 }
  end
end
