control 'SV-253263' do
  title 'Windows 11 systems must be maintained at a supported servicing level.'
  desc 'Windows 11 is maintained by Microsoft at servicing levels for specific periods of time to support Windows as a Service. Systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities which leaves them subject to exploitation.

New versions with feature updates are planned to be released on a semi-annual basis with an estimated support timeframe of 18 to 30 months depending on the release. Support for previously released versions has been extended for Enterprise editions.

A separate servicing branch intended for special purpose systems is the Long-Term Servicing Channel (LTSC, formerly Branch - LTSB) which will receive security updates for 10 years but excludes feature updates.'
  desc 'check', 'Run "winver.exe".

If the "About Windows" dialog box does not display "Microsoft Windows 11 Version 22H2 (OS Build 22621.380)" or greater, this is a finding.'
  desc 'fix', 'Update systems on the Semi-Annual Channel to "Microsoft Windows 11 Version 22H2 (OS Build 22621.380)" or greater.'
  impact 0.7
  tag check_id: 'C-56716r1016362_chk'
  tag severity: 'high'
  tag gid: 'V-253263'
  tag rid: 'SV-253263r1016364_rule'
  tag stig_id: 'WN11-00-000040'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56666r1016363_fix'
  tag 'documentable'
  tag legacy: ['V-63349', 'SV-77839']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion') do
    it { should have_property 'CurrentVersion' }
    its('CurrentVersion') { should be >= '6.3' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion') do
    it { should have_property 'CurrentBuildNumber' }
    its('ReleaseId') { should be >= '1703' }
  end
end
