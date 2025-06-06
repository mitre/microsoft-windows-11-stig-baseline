control 'SV-253260' do
  title 'Windows 11 systems must use a BitLocker PIN for pre-boot authentication.'
  desc 'If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can remove non-volatile memory and read it directly, thereby circumventing operating system controls. Encrypting the data ensures that confidentiality is protected even when the operating system is not running. Pre-boot authentication prevents unauthorized users from accessing encrypted drives.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

For virtual desktop implementations (VDIs) in which the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

For AVD implementations with no data at rest, this is NA.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\FVE\\

Value Name: UseAdvancedStartup
Type: REG_DWORD
Value: 0x00000001 (1)

If one of the following registry values does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\FVE\\

Value Name: UseTPMPIN
Type: REG_DWORD
Value: 0x00000001 (1)

Value Name: UseTPMKeyPIN
Type: REG_DWORD
Value: 0x00000001 (1)

When BitLocker network unlock is used:

Value Name: UseTPMPIN
Type: REG_DWORD
Value: 0x00000002 (2)

Value Name: UseTPMKeyPIN
Type: REG_DWORD
Value: 0x00000002 (2)

BitLocker network unlock may be used in conjunction with a BitLocker PIN. See the article below regarding information about network unlock.

https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-how-to-enable-network-unlock'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> BitLocker Drive Encryption >> Operating System Drives "Require additional authentication at startup" to "Enabled" with "Configure TPM Startup PIN:" set to "Require startup PIN with TPM" or with "Configure TPM startup key and PIN:" set to "Require startup key and PIN with TPM".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56713r828862_chk'
  tag severity: 'high'
  tag gid: 'V-253260'
  tag rid: 'SV-253260r958872_rule'
  tag stig_id: 'WN11-00-000031'
  tag gtitle: 'SRG-OS-000405-GPOS-00184'
  tag fix_id: 'F-56663r828863_fix'
  tag 'documentable'
  tag legacy: ['SV-104689', 'V-94859']
  tag cci: ['CCI-001199', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'SC-28 (1)']

  if sys_info.manufacturer == 'VMware, Inc.'
    impact 0.0
    describe 'This is a VDI System; This System is N/A for Control SV-253260' do
      skip 'This is a VDI System; This System is N/A for Control SV-253260'
    end
  else
    describe.one do
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE') do
        it { should have_property 'UseAdvancedStartup' }
        its('UseAdvancedStartup') { should cmp 1 }
      end
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE') do
        it { should have_property 'UseTPMPIN' }
        its('UseTPMPIN') { should cmp 1 }
      end
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE') do
        it { should have_property 'UseTPMKeyPIN' }
        its('UseTPMKeyPIN') { should cmp 1 }
      end
    end
  end
end
