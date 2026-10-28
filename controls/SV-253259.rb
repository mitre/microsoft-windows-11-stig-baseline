control 'SV-253259' do
  title 'Windows 11 information systems must use BitLocker to encrypt all disks to protect the confidentiality and integrity of all information at rest.'
  desc 'If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can remove nonvolatile memory and read it directly, thereby circumventing operating system controls. Encrypting the data ensures that confidentiality is protected even when the operating system is not running.'
  desc 'check', 'For AVD implementations with no data at rest, this is NA.

Verify all Windows 11 information systems (including SIPRNet) employ BitLocker for full disk encryption.

If full disk encryption using BitLocker is not implemented, this is a finding.

Verify BitLocker is turned on for the operating system drive and any fixed data drives.

Open "BitLocker Drive Encryption" from the Control Panel.

If the operating system drive or any fixed data drives have "Turn on BitLocker", this is a finding.

Note: An alternate encryption application may be used in lieu of BitLocker providing it is configured for full disk encryption and satisfies the pre-boot authentication requirements (WN11-00-000031 and WN11-00-000032).'
  desc 'fix', 'Enable full disk encryption on all information systems (including SIPRNet) using BitLocker.

BitLocker, included in Windows, can be enabled in the Control Panel under "BitLocker Drive Encryption" as well as other management tools.

Note: An alternate encryption application may be used in lieu of BitLocker providing it is configured for full disk encryption and satisfies the pre-boot authentication requirements (WN11-00-000031 and WN11-00-000032).'
  impact 0.7
  tag check_id: 'C-56712r1210184_chk'
  tag severity: 'high'
  tag gid: 'V-253259'
  tag rid: 'SV-253259r1210282_rule'
  tag stig_id: 'WN11-00-000030'
  tag gtitle: 'SRG-OS-000404-GPOS-00183'
  tag fix_id: 'F-56662r828860_fix'
  tag 'documentable'
  tag legacy: ['SV-77827', 'V-63337']
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']

  if input('avd_no_data_at_rest') == 'true'
    impact 0.0
    describe 'This is an AVD implementation with no data at rest; This System is N/A for Control SV-253259' do
      skip 'This is an AVD implementation with no data at rest; This System is N/A for Control SV-253259'
    end
  else
    # Operating system drive and fixed data drives (MSFT_Volume DriveType 3 = Fixed)
    volumes = json(command: <<~PS).params
      $fixed = Get-CimInstance -Namespace root\\Microsoft\\Windows\\Storage -ClassName MSFT_Volume |
        Where-Object { $_.DriveType -eq 3 -and $_.DriveLetter } |
        ForEach-Object { "$($_.DriveLetter):" }
      $volumes = Get-BitLockerVolume | Where-Object { $fixed -contains $_.MountPoint } |
        Select-Object MountPoint, @{ n = 'VolumeType'; e = { "$($_.VolumeType)" } }, @{ n = 'ProtectionStatus'; e = { "$($_.ProtectionStatus)" } }
      ConvertTo-Json -InputObject @($volumes)
    PS

    describe 'Operating system and fixed data drives reported by Get-BitLockerVolume' do
      subject { volumes }
      it { should_not be_empty }
    end
    volumes.each do |volume|
      describe "BitLocker protection status of #{volume['VolumeType']} drive #{volume['MountPoint']}" do
        subject { volume['ProtectionStatus'] }
        it { should cmp 'On' }
      end
    end
  end
end
