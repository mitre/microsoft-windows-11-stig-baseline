control 'SV-253271' do
  title 'Only authorized user accounts must be allowed to create or run virtual machines on Windows 11 systems.'
  desc 'Allowing other operating systems to run on a secure system may allow users to circumvent security. For Hyper-V, preventing unauthorized users from being assigned to the Hyper-V Administrators group will prevent them from accessing or creating virtual machines on the system. The Hyper-V Hypervisor is used by virtualization-based Security features such as Credential Guard on Windows 11; however, it is not the full Hyper-V installation.'
  desc 'check', 'If a hosted hypervisor (Hyper-V, VMware Workstation, etc.) is installed on the system, verify only authorized user accounts are allowed to run virtual machines.

For Hyper-V, run "Computer Management".
Navigate to System Tools >> Local Users and Groups >> Groups.
Double click on "Hyper-V Administrators".

If any unauthorized groups or user accounts are listed in "Members:", this is a finding.

For hosted hypervisors other than Hyper-V, verify only authorized user accounts have access to run the virtual machines. Restrictions may be enforced by access to the physical system, software restriction policies, or access restrictions built into the application.

If any unauthorized groups or user accounts have access to create or run virtual machines, this is a finding.

All users authorized to create or run virtual machines must be documented with the ISSM/ISSO. Accounts nested within group accounts must be documented as individual accounts and not the group accounts.'
  desc 'fix', 'For Hyper-V, remove any unauthorized groups or user accounts from the "Hyper-V Administrators" group.

For hosted hypervisors other than Hyper-V, restrict access to create or run virtual machines to authorized user accounts only.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56724r828895_chk'
  tag severity: 'medium'
  tag gid: 'V-253271'
  tag rid: 'SV-253271r958702_rule'
  tag stig_id: 'WN11-00-000080'
  tag gtitle: 'SRG-OS-000312-GPOS-00124'
  tag fix_id: 'F-56674r828896_fix'
  tag 'documentable'
  tag legacy: ['SV-77855', 'V-63365']
  tag cci: ['CCI-000381', 'CCI-002165']
  tag nist: ['CM-7 a', 'AC-3 (4)']

  hyper_v_administrator_group = command("net localgroup Hyper-V Administrators | Format-List | Findstr /V 'Alias Name Comment Members - command'").stdout.strip.split("\r\n")

  hyper_v_administrator_group.each do |user|
    describe user.to_s do
      it { should be_in input('hyper_v_admin') }
    end
  end
  if hyper_v_administrator_group.empty?
    impact 0.0
    describe 'There are no users with administrative privileges' do
      skip 'This control is not applicable'
    end
  end
end
