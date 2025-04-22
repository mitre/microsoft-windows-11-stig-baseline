control 'SV-257592' do
  title 'Windows 11 must not have portproxy enabled or in use.'
  desc 'Having portproxy enabled or configured in Windows 10 could allow a man-in-the-middle attack.'
  desc 'check', 'Check the registry key for existence of proxied ports:
HKLM\\SYSTEM\\CurrentControlSet\\Services\\PortProxy\\.

If the key contains v4tov4\\tcp\\ or is populated v4tov4\\tcp\\, this is a finding.

Run "netsh interface portproxy show all".

If the command displays any results, this is a finding.'
  desc 'fix', 'Contact the Administrator to run "netsh interface portproxy delete" with elevation. Remove any enabled portproxies that may be configured.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-61332r922045_chk'
  tag severity: 'medium'
  tag gid: 'V-257592'
  tag rid: 'SV-257592r991589_rule'
  tag stig_id: 'WN11-00-000395'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61256r922046_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # test 1, seems like checking if registry doesnt have something is complicated, since registry_key requires a key to check
  # describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PortProxy') do
  #   it { should_not exist }
  # end

  describe powershell('netsh interface portproxy show all') do
    its('stdout.strip') { should be_empty }
  end
end
