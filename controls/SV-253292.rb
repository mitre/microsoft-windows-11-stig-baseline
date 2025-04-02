control 'SV-253292' do
  title 'Bluetooth must be turned off when not in use.'
  desc 'If not configured properly, Bluetooth may allow rogue devices to communicate with a system. If a rogue device is paired with a system, there is potential for sensitive information to be compromised.'
  desc 'check', 'This is NA if the system does not have Bluetooth.

Verify the organization has a policy to turn off Bluetooth when not in use and personnel are trained. If it does not, this is a finding.'
  desc 'fix', 'Turn off Bluetooth radios when not in use. Establish an organizational policy for the use of Bluetooth to include training of personnel.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56745r828958_chk'
  tag severity: 'medium'
  tag gid: 'V-253292'
  tag rid: 'SV-253292r958478_rule'
  tag stig_id: 'WN11-00-000220'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56695r828959_fix'
  tag 'documentable'
  tag legacy: ['V-72767', 'SV-87405']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  if sys_info.manufacturer == 'VMware, Inc.'
    impact 0.0
    describe 'This is a VDI System; This Control is NA.' do
      skip 'This is a VDI System; This Control is NA'
    end
  else
    describe 'Turn off Bluetooth radios when not in use. Establish an organizational policy for the use of Bluetooth to include training of personnel' do
      skip 'This is NA if the system does not have Bluetooth'
    end
  end
end
