control 'SV-253436' do
  title 'The built-in guest account must be renamed.'
  desc 'The built-in guest account is a well-known user account on all Windows systems and, as initially installed, does not require a password.  This can allow access to system resources by unauthorized users.  Renaming this account to an unidentified name improves the protection of this account and the system.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Accounts: Rename guest account" is set to "Guest", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Accounts: Rename guest account" to a name other than "Guest".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56889r829390_chk'
  tag severity: 'medium'
  tag gid: 'V-253436'
  tag rid: 'SV-253436r991589_rule'
  tag stig_id: 'WN11-SO-000025'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56839r829391_fix'
  tag 'documentable'
  tag legacy: ['SV-78115', 'V-63625']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe user('Guest') do
    it { should_not exist }
  end
end
