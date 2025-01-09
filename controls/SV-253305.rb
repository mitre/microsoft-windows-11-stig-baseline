control 'SV-253305' do
  title 'Reversible password encryption must be disabled.'
  desc 'Storing passwords using reversible encryption is essentially the same as storing clear-text versions of the passwords. For this reason, this policy must never be enabled.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for "Store password using reversible encryption" is not set to "Disabled", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> "Store passwords using reversible encryption" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56758r828997_chk'
  tag severity: 'high'
  tag gid: 'V-253305'
  tag rid: 'SV-253305r1016431_rule'
  tag stig_id: 'WN11-AC-000045'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-56708r828998_fix'
  tag 'documentable'
  tag legacy: ['SV-77919', 'V-63429']
  tag cci: ['CCI-004062', 'CCI-000196']
  tag nist: ['IA-5 (1) (d)', 'IA-5 (1) (c)']

  describe security_policy do
    its('ClearTextPassword') { should eq 0 }
  end
end
