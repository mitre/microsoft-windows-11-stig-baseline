control 'SV-253280' do
  title 'Software certificate installation files must be removed from Windows 11.'
  desc 'Use of software certificates and their accompanying installation files for end users to access resources is less secure than the use of hardware-based certificates.'
  desc 'check', 'Search all drives for *.p12 and *.pfx files.

If any files with these extensions exist, this is a finding.

This does not apply to server-based applications that have a requirement for .p12 certificate files (e.g., Oracle Wallet Manager) or Adobe PreFlight certificate files. Some applications create files with extensions of .p12 that are not certificate installation files. Removal of non-certificate installation files from systems is not required. These must be documented with the ISSO.'
  desc 'fix', 'Remove any certificate installation files (*.p12 and *.pfx) found on a system.

Note: This does not apply to server-based applications that have a requirement for .p12 certificate files (e.g., Oracle Wallet Manager) or Adobe PreFlight certificate files.'
  impact 0.5
  tag check_id: 'C-56733r828922_chk'
  tag severity: 'medium'
  tag gid: 'V-253280'
  tag rid: 'SV-253280r991589_rule'
  tag stig_id: 'WN11-00-000130'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56683r828923_fix'
  tag 'documentable'
  tag legacy: ['V-63393', 'SV-77883']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('where /R c: *.p12 *.pfx') do
    its('stdout') { should eq '' }
  end
end
