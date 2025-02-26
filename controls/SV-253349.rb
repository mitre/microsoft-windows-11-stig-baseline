control 'SV-253349' do
  title 'Windows 11 must be configured to audit MPSSVC Rule-Level Policy Change Failures.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit MPSSVC Rule-Level Policy Change determines whether the operating system generates audit events when changes are made to policy rules for the Microsoft Protection Service (MPSSVC.exe).'
  desc 'check', 'Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding:

Policy Change >> MPSSVC Rule-Level Policy Change - Failure'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Policy Change >> Audit MPSSVC Rule-Level Policy Change" with "Failure" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56802r829129_chk'
  tag severity: 'medium'
  tag gid: 'V-253349'
  tag rid: 'SV-253349r958412_rule'
  tag stig_id: 'WN11-AU-000580'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-56752r829130_fix'
  tag 'documentable'
  tag legacy: ['V-99549', 'SV-108653']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']

  describe.one do
    describe audit_policy do
      its('MPSSVC Rule-Level Policy Change') { should eq 'Failure' }
    end
    describe audit_policy do
      its('MPSSVC Rule-Level Policy Change') { should eq 'Success and Failure' }
    end
  end
end
