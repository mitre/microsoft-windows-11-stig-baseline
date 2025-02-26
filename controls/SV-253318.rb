control 'SV-253318' do
  title 'The system must be configured to audit Logon/Logoff - Special Logon successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Special Logon records special logons which have administrative privileges and can be used to elevate processes.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN11-SO-000030) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding:

Logon/Logoff >> Special Logon - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff >> "Audit Special Logon" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56771r829036_chk'
  tag severity: 'medium'
  tag gid: 'V-253318'
  tag rid: 'SV-253318r991578_rule'
  tag stig_id: 'WN11-AU-000080'
  tag gtitle: 'SRG-OS-000470-GPOS-00214'
  tag fix_id: 'F-56721r829037_fix'
  tag 'documentable'
  tag legacy: ['V-63469', 'SV-77959']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe.one do
    describe audit_policy do
      its('Special Logon') { should eq 'Success' }
    end
    describe audit_policy do
      its('Special Logon') { should eq 'Success and Failure' }
    end
  end
end
