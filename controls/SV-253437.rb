control 'SV-253437' do
  title 'Audit policy using subcategories must be enabled.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.  This setting allows administrators to enable more precise auditing capabilities.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: SCENoApplyLegacyAuditPolicy

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56890r829393_chk'
  tag severity: 'medium'
  tag gid: 'V-253437'
  tag rid: 'SV-253437r958442_rule'
  tag stig_id: 'WN11-SO-000030'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-56840r829394_fix'
  tag 'documentable'
  tag legacy: ['V-63635', 'SV-78125']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should have_property 'SCENoApplyLegacyAuditPolicy' }
    its('SCENoApplyLegacyAuditPolicy') { should cmp 1 }
  end
end
