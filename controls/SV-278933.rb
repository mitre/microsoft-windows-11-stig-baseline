control 'SV-278933' do
  title 'Windows 11 must be configured to audit sensitive privilege use failures.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. Credential validation records events related to validation tests on credentials for a user account logon.'
  desc 'check', 'Verify that Audit Sensitive Privilege Use auditing has been enabled: 

Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Privilege Use >> Audit Sensitive Privilege Use. 

If "Audit Sensitive Privilege Use" is not set to "Failure", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Privilege Use >> Audit Sensitive Privilege Use with "Failure" selected.'
  impact 0.5
  tag check_id: 'C-83467r1141917_chk'
  tag severity: 'medium'
  tag gid: 'V-278933'
  tag rid: 'SV-278933r1141919_rule'
  tag stig_id: 'WN11-AU-000588'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-83372r1141918_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe audit_policy do
    its('Sensitive Privilege Use') { should match 'Failure' }
  end
end
