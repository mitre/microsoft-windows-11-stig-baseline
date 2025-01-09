control 'SV-253265' do
  title 'Local volumes must be formatted using NTFS.'
  desc 'The ability to set access permissions and auditing is critical to maintaining the security and proper access controls of a system.  To support this, volumes must be formatted using the NTFS file system.'
  desc 'check', 'Run "Computer Management".
Navigate to Storage >> Disk Management.

If the "File System" column does not indicate "NTFS" for each volume assigned a drive letter, this is a finding.

This does not apply to system partitions such the Recovery and EFI System Partition.'
  desc 'fix', 'Format all local volumes to use NTFS.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56718r828877_chk'
  tag severity: 'high'
  tag gid: 'V-253265'
  tag rid: 'SV-253265r958472_rule'
  tag stig_id: 'WN11-00-000050'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-56668r828878_fix'
  tag 'documentable'
  tag legacy: ['SV-77843', 'V-63353']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

get_volumes = command("wmic logicaldisk get FileSystem | findstr /r /v '^$' |Findstr /v 'FileSystem'").stdout.strip.split("\r\n")

  if get_volumes.empty?
    impact 0.0
    describe 'There are no local volumes' do
      skip 'This control is not applicable'
    end
  else
    get_volumes.each do |volume|
      volumes = volume.strip
      describe.one do
        describe 'The format local volumes' do
          subject { volumes }
          it { should eq 'NTFS' }
        end
        describe 'The format local volumes' do
          subject { volumes }
          it { should eq 'ReFS' }
        end
      end
    end
  end
end
