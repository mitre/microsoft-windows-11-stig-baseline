control 'SV-253383' do
  title 'Unauthenticated RPC clients must be restricted from connecting to the RPC server.'
  desc 'Configuring RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent anonymous connections.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc\\

Value Name: RestrictRemoteClients

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Remote Procedure Call >> "Restrict Unauthenticated RPC clients" to "Enabled" and "Authenticated".'
  impact 0.5
  tag check_id: 'C-56836r829231_chk'
  tag severity: 'medium'
  tag gid: 'V-253383'
  tag rid: 'SV-253383r971545_rule'
  tag stig_id: 'WN11-CC-000165'
  tag gtitle: 'SRG-OS-000379-GPOS-00164'
  tag fix_id: 'F-56786r829232_fix'
  tag 'documentable'
  tag legacy: ['V-63657', 'SV-78147']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc') do
    it { should have_property 'RestrictRemoteClients' }
    its('RestrictRemoteClients') { should cmp 1 }
  end
end
