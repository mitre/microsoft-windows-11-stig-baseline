control 'SV-253295' do
  title 'Windows 11 nonpersistent VM sessions must not exceed 24 hours.'
  desc 'For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon logoff, the organization must enforce that sessions be terminated within 24 hours. This would ensure any data stored on the VM that is not encrypted or covered by Credential Guard is deleted.'
  desc 'check', 'Verify there is a documented policy or procedure in place that nonpersistent VM sessions do not exceed 24 hours.                                                                                                                                                                                                                                                                                                  

If the system is NOT a nonpersistent VM, this is Not Applicable. 

For Azure Virtual Desktop (AVD) implementations with no data at rest, this is Not Applicable.

If there is no such documented policy or procedure in place, this is a finding.'
  desc 'fix', 'Set nonpersistent VM sessions to not exceed 24 hours.'
  impact 0.5
  tag check_id: 'C-56748r890450_chk'
  tag severity: 'medium'
  tag gid: 'V-253295'
  tag rid: 'SV-253295r958552_rule'
  tag stig_id: 'WN11-00-000250'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-56698r890451_fix'
  tag 'documentable'
  tag legacy: ['V-102611', 'SV-111557']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']

  # Not applicable on physical (non-virtual) systems
  if virtualization.physical_system?
    impact 0.0
    describe 'This system is not a virtual machine' do
      skip 'This control applies only to nonpersistent virtual machines.'
    end
  else
    # Virtual machine → manual review per STIG
    describe 'Windows 11 nonpersistent VM sessions' do
      skip 'Verify documented policy ensuring nonpersistent VM sessions do not exceed 24 hours.'
    end
  end
end
