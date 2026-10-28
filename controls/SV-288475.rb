control 'SV-288475' do
  title 'All Wi-Fi Direct adapters must be disabled on the system.'
  desc 'Wi-Fi Direct establishes a peer-to-peer (P2P) connection that lacks robust authentication. Due to its vulnerability to several types of attacks (including SSID spoofing and unauthorized network bridge), there is potential for sensitive information to be compromised.'
  desc 'check', 'Determine whether any Wi-Fi Direct adapters exist on the system.
 
Open PowerShell with elevated privileges (run as administrator).
 
Enter the following command:

Get-NetAdapter -InterfaceDescription "Microsoft Wi-Fi Direct*" -IncludeHidden
 
If there are no Wi-Fi Direct adapters configured on the system, no adapter information will display. 
 
If any Wi-Fi Direct adapters are listed, this is a finding.'
  desc 'fix', 'Remove existing Wi-Fi Direct adapters from the system.
 
Open PowerShell with elevated privileges (run as administrator).
 
Enter the following command:

Get-NetAdapter -InterfaceDescription "Microsoft Wi-Fi Direct*" -IncludeHidden | Disable-NetAdapter -Confirm:$false".'
  impact 0.5
  tag check_id: 'C-93164r1256667_chk'
  tag severity: 'medium'
  tag gid: 'V-288475'
  tag rid: 'SV-288475r1256669_rule'
  tag stig_id: 'WN11-00-000400'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-93069r1256668_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  wifi_direct_adapters = json(command: <<~PS).params
    $adapters = Get-NetAdapter -InterfaceDescription 'Microsoft Wi-Fi Direct*' -IncludeHidden -ErrorAction SilentlyContinue |
      Select-Object Name, InterfaceDescription, @{ n = 'Status'; e = { "$($_.Status)" } }
    ConvertTo-Json -InputObject @($adapters)
  PS

  if wifi_direct_adapters.empty?
    describe 'Wi-Fi Direct adapters present on the system' do
      subject { wifi_direct_adapters }
      it { should be_empty }
    end
  else
    wifi_direct_adapters.each do |adapter|
      describe "Wi-Fi Direct adapter #{adapter['Name']} (#{adapter['InterfaceDescription']})" do
        subject { adapter['Status'] }
        it { should cmp 'Disabled' }
      end
    end
  end
end
