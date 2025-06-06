control 'SV-253351' do
  title 'Windows 11 must cover or disable the built-in or attached camera when not in use.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Failing to disconnect from collaborative computing devices (i.e. cameras) can result in subsequent compromises of organizational information. Providing easy methods to physically disconnect from such devices after a collaborative computing session helps to ensure that participants actually carry out the disconnect activity without having to go through complex and tedious procedures.'
  desc 'check', 'If the device or operating system does not have a camera installed, this requirement is not applicable.

This requirement is not applicable to mobile devices (smartphones and tablets), where the use of the camera is a local AO decision.

This requirement is not applicable to dedicated VTC suites located in approved VTC locations that are centrally managed.

For an external camera, if there is not a method for the operator to manually disconnect camera at the end of collaborative computing sessions, this is a finding.

For a built-in camera, the camera must be protected by a camera cover (e.g. laptop camera cover slide) when not in use. If the built-in camera is not protected with a camera cover, or if the built-in
camera is not disabled in the bios, this is a finding.

If the camera is not disconnected or covered, the following registry entry is required:

Registry Hive: HKEY_LOCAL_MACHINE
RegistryPath\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam

Value Name: Deny

If "Value Name" is set to a value other than "Deny" and the collaborative computing device has not been authorized for use, this is a finding.'
  desc 'fix', 'If the camera is not disconnected or covered, the following registry entry is required.

Registry Hive: HKEY_LOCAL_MACHINE
RegistryPath\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam

Value Name: Deny'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56804r829135_chk'
  tag severity: 'medium'
  tag gid: 'V-253351'
  tag rid: 'SV-253351r958478_rule'
  tag stig_id: 'WN11-CC-000007'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56754r829136_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag legacy: ['SV-109197', 'V-100093']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp') do
    it { should_not exist }
  end

  describe powershell('netsh interface portproxy show all') do
    its('stdout.strip') { should be_empty }
  end
end
