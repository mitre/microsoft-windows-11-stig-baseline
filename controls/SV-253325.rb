control 'SV-253325' do
  title 'The system must be configured to audit Policy Change - Audit Policy Change successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit Policy Change records events related to changes in audit policy.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings to override audit policy category settings" must be set to "Enabled" (WN11-SO-000030) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding:

Policy Change >> Audit Policy Change - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Policy Change >> "Audit Policy Change" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56778r829057_chk'
  tag severity: 'medium'
  tag gid: 'V-253325'
  tag rid: 'SV-253325r991572_rule'
  tag stig_id: 'WN11-AU-000100'
  tag gtitle: 'SRG-OS-000462-GPOS-00206'
  tag fix_id: 'F-56728r829058_fix'
  tag 'documentable'
  tag legacy: ['SV-77969', 'V-63479']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe.one do
    describe audit_policy do
      its('Audit Policy Change') { should eq 'Success' }
    end
    describe audit_policy do
      its('Audit Policy Change') { should eq 'Success and Failure' }
    end
  end
end
