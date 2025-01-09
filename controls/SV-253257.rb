control 'SV-253257' do
  title 'Secure Boot must be enabled on Windows 11 systems.'
  desc 'Secure Boot is a standard that ensures systems boot only to a trusted operating system. Secure Boot is required to support additional security features in Windows 11, including virtualization-based Security and Credential Guard. If Secure Boot is turned off, these security features will not function.'
  desc 'check', 'Verify the system firmware is configured for Secure Boot.

For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Run "System Information".

Under "System Summary", if "Secure Boot State" does not display "On", this is a finding.'
  desc 'fix', 'Enable Secure Boot in the system firmware.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56710r828853_chk'
  tag severity: 'medium'
  tag gid: 'V-253257'
  tag rid: 'SV-253257r971547_rule'
  tag stig_id: 'WN11-00-000020'
  tag gtitle: 'SRG-OS-000424-GPOS-00188'
  tag fix_id: 'F-56660r828854_fix'
  tag 'documentable'
  tag legacy: ['SV-91781', 'V-77085']
  tag cci: ['CCI-000366', 'CCI-002421']
  tag nist: ['CM-6 b', 'SC-8 (1)']

  uefi_boot = json( command: 'Confirm-SecureBootUEFI | ConvertTo-Json').params
  if sys_info.manufacturer != 'VMware, Inc.' || nil
    describe 'Confirm-Secure Boot UEFI is required to be enabled on System' do
      subject { uefi_boot }
      it { should_not eq 'False' }
    end
  else
    impact 0.0
    describe 'This is a VDI System; This System is NA for Control V-77085.' do
      skip 'This is a VDI System; This System is NA for Control V-77085.'
    end
  end
end
