control 'SV-253273' do
  title 'Accounts must be configured to require password expiration.'
  desc 'Passwords that do not expire increase exposure with a greater probability of being discovered or cracked.'
  desc 'check', 'Run "Computer Management".
Navigate to System Tools >> Local Users and Groups >> Users.
Double-click each active account.

If "Password never expires" is selected for any account, this is a finding.'
  desc 'fix', 'Configure all passwords to expire.
Run "Computer Management".
Navigate to System Tools >> Local Users and Groups >> Users.
Double-click each active account.
Ensure "Password never expires" is not checked on all active accounts.'
  impact 0.5
  tag check_id: 'C-56726r828901_chk'
  tag severity: 'medium'
  tag gid: 'V-253273'
  tag rid: 'SV-253273r1051040_rule'
  tag stig_id: 'WN11-00-000090'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-56676r828902_fix'
  tag 'documentable'
  tag legacy: ['V-63371', 'SV-77861']
  tag cci: ['CCI-004066', 'CCI-000199']
  tag nist: ['IA-5 (1) (h)', 'IA-5 (1) (d)']

  describe command("Get-CimInstance -Class Win32_Useraccount -Filter 'PasswordExpires=False
  and LocalAccount=True and Disabled=False' | FT Name | Findstr /V 'Name --'") do
    its('stdout') { should eq '' }
  end
end
