control 'SV-253291' do
  title 'Bluetooth must be turned off unless approved by the organization.'
  desc 'If not configured properly, Bluetooth may allow rogue devices to communicate with a system. If a rogue device is paired with a system, there is potential for sensitive information to be compromised.'
  desc 'check', 'This is NA if the system does not have Bluetooth.

Verify the Bluetooth radio is turned off unless approved by the organization. If it is not, this is a finding.

Approval must be documented with the ISSO.'
  desc 'fix', 'Turn off Bluetooth radios not organizationally approved. Establish an organizational policy for the use of Bluetooth.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56744r828955_chk'
  tag severity: 'medium'
  tag gid: 'V-253291'
  tag rid: 'SV-253291r958478_rule'
  tag stig_id: 'WN11-00-000210'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56694r828956_fix'
  tag 'documentable'
  tag legacy: ['SV-87403', 'V-72765']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  if sys_info.manufacturer == 'VMware, Inc.'
    impact 0.0
    describe 'This is a VDI System; This System is N/A for Control SV-253291' do
      skip 'This is a VDI System; This System is N/A for Control SV-253291'
    end
  else
    describe 'Turn off Bluetooth radios when not in use. Establish an organizational policy for the use of Bluetooth to include training of personnel' do
      skip 'This is NA if the system does not have Bluetooth'
    end
  end
end
