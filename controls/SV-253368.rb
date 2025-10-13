control 'SV-253368' do
  title 'Windows 11 must be configured to enable Remote host allows delegation of non-exportable credentials.'
  desc 'An exportable version of credentials is provided to remote hosts when using credential delegation which exposes them to theft on the remote host.  Restricted Admin mode or Remote Credential Guard allow delegation of non-exportable credentials providing additional protection of the credentials.  Enabling this configures the host to support Restricted Admin mode or Remote Credential Guard.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation\\

Value Name: AllowProtectedCreds

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Credentials Delegation >> "Remote host allows delegation of non-exportable credentials" to "Enabled".'
  impact 0.5
  tag check_id: 'C-56821r829186_chk'
  tag severity: 'medium'
  tag gid: 'V-253368'
  tag rid: 'SV-253368r991589_rule'
  tag stig_id: 'WN11-CC-000068'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56771r829187_fix'
  tag 'documentable'
  tag legacy: ['SV-89373', 'V-74699']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  releaseID = registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId.to_i

  if releaseID == 1607 || releaseID <= 1507
    impact 0.0
    describe 'This STIG does not apply to Prior Versions before 1507 and 1607.' do
      skip 'This STIG does not apply to Prior Versions before 1507 and 1607.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation') do
      it { should have_property 'AllowProtectedCreds' }
      its('AllowProtectedCreds') { should cmp 1 }
    end
  end
end
