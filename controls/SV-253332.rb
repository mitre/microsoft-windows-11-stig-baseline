control 'SV-253332' do
  title 'The system must be configured to audit System - Other System Events failures.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit Other System Events records information related to cryptographic key operations and the Windows Firewall service.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings to override audit policy category settings" must be set to "Enabled" (WN11-SO-000030) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*"

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding:

System >> Other System Events - Failure'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> System >> "Audit Other System Events" with "Failure" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56785r829078_chk'
  tag severity: 'medium'
  tag gid: 'V-253332'
  tag rid: 'SV-253332r991579_rule'
  tag stig_id: 'WN11-AU-000135'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-56735r829079_fix'
  tag 'documentable'
  tag legacy: ['SV-77993', 'V-63503']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe.one do
    describe audit_policy do
      its('Other System Events') { should eq 'Failure' }
    end
    describe audit_policy do
      its('Other System Events') { should eq 'Success and Failure' }
    end
  end
end
