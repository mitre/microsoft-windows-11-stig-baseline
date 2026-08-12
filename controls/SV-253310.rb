control 'SV-253310' do
  title 'The system must be configured to audit Account Management - User Account Management successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

User Account Management records events such as creating, changing, deleting, renaming, disabling, or enabling user accounts.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings to override audit policy category settings" must be set to "Enabled" (WN11-SO-000030) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding:

Account Management >> User Account Management - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management >> "Audit User Account Management" with "Success" selected.'
  impact 0.5
  tag check_id: 'C-56763r829012_chk'
  tag severity: 'medium'
  tag gid: 'V-253310'
  tag rid: 'SV-253310r991551_rule'
  tag stig_id: 'WN11-AU-000040'
  tag gtitle: 'SRG-OS-000239-GPOS-00089'
  tag fix_id: 'F-56713r829013_fix'
  tag 'documentable'
  tag legacy: ['SV-77939', 'V-63449']
  tag cci: ['CCI-000018', 'CCI-000172', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-002130', 'CCI-002234']
  tag nist: ['AC-2 (4)', 'AU-12 c', 'AC-6 (9)']

  describe.one do
    describe audit_policy do
      its('User Account Management') { should eq 'Success' }
    end
    describe audit_policy do
      its('User Account Management') { should eq 'Success and Failure' }
    end
  end
end
