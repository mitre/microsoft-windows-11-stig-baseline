control 'SV-253409' do
  title 'Indexing of encrypted files must be turned off.'
  desc 'Indexing of encrypted files may expose sensitive data. This setting prevents encrypted files from being indexed.

Note: A different registry location is needed when systems are managed by Intune versus GPO.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\\  (For GPO-managed systems)
Or
Registry Path: \\Software\\Microsoft\\Policymanager\\current\\device\\search  (For Intune-managed systems)
 
Value Name: AllowIndexingEncryptedStoresOrItems

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'For GPO-managed systems:

Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Search >> "Allow indexing of encrypted files" to "Disabled".

For Intune-managed systems:

Revise the Intune policy to disable indexing of encrypted files.'
  impact 0.5
  tag check_id: 'C-56862r1210221_chk'
  tag severity: 'medium'
  tag gid: 'V-253409'
  tag rid: 'SV-253409r1210297_rule'
  tag stig_id: 'WN11-CC-000305'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56812r1210222_fix'
  tag 'documentable'
  tag legacy: ['V-63751', 'SV-78241']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # GPO-managed systems use the Windows Search policy key; Intune-managed systems use the Search CSP
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search') do
      it { should have_property 'AllowIndexingEncryptedStoresOrItems' }
      its('AllowIndexingEncryptedStoresOrItems') { should cmp 0 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Search') do
      it { should have_property 'AllowIndexingEncryptedStoresOrItems' }
      its('AllowIndexingEncryptedStoresOrItems') { should cmp 0 }
    end
  end
end
