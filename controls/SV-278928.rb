control 'SV-278928' do
  title 'Windows 11 must be configured to audit handle manipulation failures.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. Credential validation records events related to validation tests on credentials for a user account logon.'
  desc 'check', 'Verify that Audit Handle Manipulation auditing has been enabled: 

Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Object Access >> Audit Handle Manipulation. 

If "Audit Handle Manipulation" is not set to "Failure", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Object Access >> "Audit Handle Manipulation" with "Failure" selected.'
  impact 0.5
  tag check_id: 'C-83462r1135300_chk'
  tag severity: 'medium'
  tag gid: 'V-278928'
  tag rid: 'SV-278928r1135302_rule'
  tag stig_id: 'WN11-AU-000583'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-83367r1135301_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe audit_policy do
    its('Handle Manipulation') { should match 'Failure' }
  end
end
