control 'SV-253407' do
  title 'Attachments must be prevented from being downloaded from RSS feeds.'
  desc 'Attachments from RSS feeds may not be secure.  This setting will prevent attachments from being downloaded from RSS feeds.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

Value Name: DisableEnclosureDownload

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> RSS Feeds >> "Prevent downloading of enclosures" to "Enabled".'
  impact 0.5
  tag check_id: 'C-56860r829303_chk'
  tag severity: 'medium'
  tag gid: 'V-253407'
  tag rid: 'SV-253407r991589_rule'
  tag stig_id: 'WN11-CC-000295'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56810r829304_fix'
  tag 'documentable'
  tag legacy: ['SV-78233', 'V-63743']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds') do
    it { should have_property 'DisableEnclosureDownload' }
    its('DisableEnclosureDownload') { should cmp 1 }
  end
end
