control 'SV-253308' do
  title 'The system must be configured to audit Account Management - Security Group Management successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Security Group Management records events such as creating, deleting or changing of security groups, including changes in group members.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings to override audit policy category settings" must be set to "Enabled" (WN11-SO-000030) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding:

Account Management >> Security Group Management - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management >> "Audit Security Group Management" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56761r829006_chk'
  tag severity: 'medium'
  tag gid: 'V-253308'
  tag rid: 'SV-253308r971541_rule'
  tag stig_id: 'WN11-AU-000030'
  tag gtitle: 'SRG-OS-000337-GPOS-00129'
  tag fix_id: 'F-56711r829007_fix'
  tag 'documentable'
  tag legacy: ['SV-77935', 'V-63445']
  tag cci: ['CCI-000018', 'CCI-000172', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-002130', 'CCI-002234', 'CCI-001914']
  tag nist: ['AC-2 (4)', 'AU-12 c', 'AC-6 (9)', 'AU-12 (3)']

  describe.one do
    describe audit_policy do
      its('Security Group Management') { should eq 'Success' }
    end
    describe audit_policy do
      its('Security Group Management') { should eq 'Success and Failure' }
    end
  end
end
