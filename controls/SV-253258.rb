control 'SV-253258' do
  title 'Windows 11 must employ automated mechanisms to determine the state of system components with regard to flaw remediation using the following frequency: Continuously, where ESS is used; 30 days, for any additional internal network scans not covered by ESS; and annually, for external scans by Computer Network Defense Service Provider (CNDSP).'
  desc 'An approved tool for continuous network scanning must be installed and configured to run.

Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the operating system or other system components may remain vulnerable to the exploits presented by undetected software flaws.

To support this requirement, the operating system may have an integrated solution incorporating continuous scanning using ESS and periodic scanning using other tools, as specified in the requirement.'
  desc 'check', "Verify DOD-approved ESS software is installed and properly operating. Ask the site information system security manager (ISSM) for documentation of the ESS software installation and configuration.

If the ISSM is not able to provide a documented configuration for an installed ESS or if the ESS software is not properly maintained or used, this is a finding.

Note: Example of documentation can be a copy of the site's CCB approved Software Baseline with version of software noted or a memo from the ISSM stating current ESS software and version."
  desc 'fix', 'Install DOD-approved ESS software and ensure it is operating continuously.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56711r997864_chk'
  tag severity: 'medium'
  tag gid: 'V-253258'
  tag rid: 'SV-253258r1000099_rule'
  tag stig_id: 'WN11-00-000025'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-56661r997865_fix'
  tag 'documentable'
  tag legacy: ['SV-77833', 'V-63343']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe "A manual review is required to ensure the operating system employs automated mechanisms to determine the
  state of system components with regard to flaw remediation using the following
  frequency: continuously, where HBSS is used; 30 days, for any additional
  internal network scans not covered by HBSS; and annually, for external scans by
  Computer Network Defense Service Provider (CNDSP)." do
    skip 'A manual review is required to ensure the operating system employs automated mechanisms to determine the
  state of system components with regard to flaw remediation using the following
  frequency: continuously, where HBSS is used; 30 days, for any additional
  internal network scans not covered by HBSS; and annually, for external scans by
  Computer Network Defense Service Provider (CNDSP).'
  end
end
