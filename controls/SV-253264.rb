control 'SV-253264' do
  title 'The Windows 11 system must use an antivirus program.'
  desc 'Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.'
  desc 'check', 'Verify an organizationally approved antivirus solution (Microsoft Defender Antivirus, for example) is installed on the system and in use. 

Verify if Microsoft Defender Antivirus is in use or enabled:
If Windows Defender is your primary or secondary antivirus (AV) application, this command will use the built-in Microsoft Defender module to retrieve granular engine data.
 
Run "PowerShell" as an administrator.

Execute the following command:
Get-MpComputerStatus | Select-Object AMRunningMode, RealTimeProtectionEnabled, AntivirusEnabled, AMEngineVersion

Review the resulting display. Note the text under "AMRunningMode". This reveals how Defender is coexisting with other AV software.
"Normal" indicates Defender is active and acting as the primary AV software. 
"Passive" indicates another compatible third-party AV software is registered and active. Defender can still provide auxiliary scanning. 
"EDR Block Mode" indicates Defender is executing in Passive Mode along with a third-party AV to actively block and remediate malicious files if the primary AV misses them.
Review the text under heading of "RealTimeProtectionEnabled". A value of "True" or "False" indicates whether (or not) Defender is active (currently running). 

Verify third-party antivirus is in use or enabled:
Note: This command will display all AV applications registered with the Windows Security Center (including third-party applications).

Run "PowerShell" as an administrator.

Execute the following command:
Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState, pathToSignedProductExe

Review the resulting display. Note the text under "displayName". This will indicate the currently running AV applications.
The "productState" returns an integer value that reveals whether the AV is active, disabled, or up-to-date.
The value of "397568" indicates it is active and up-to-date.
The value of "397584 indicates it is active, but out of date (signature updates required).
The value of "393472" indicates disabled and up-to-date (AV installed, but not active).
The value of "393488" indicates disabled and out of date.

If there is no antivirus solution installed and active on the system, this is a finding.'
  desc 'fix', 'Install and activate Microsoft Defender Antivirus or a third-party antivirus solution.'
  impact 0.7
  tag check_id: 'C-56717r1259976_chk'
  tag severity: 'high'
  tag gid: 'V-253264'
  tag rid: 'SV-253264r1268251_rule'
  tag stig_id: 'WN11-00-000045'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56667r1259977_fix'
  tag 'documentable'
  tag legacy: ['SV-77841', 'V-63351']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  av_status = json(command: <<~PS).params
    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue |
      Select-Object AMRunningMode, RealTimeProtectionEnabled, AntivirusEnabled
    $products = Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
      Select-Object displayName, productState
    [pscustomobject]@{ Defender = $defender; Products = @($products) } | ConvertTo-Json -Depth 3
  PS

  defender = av_status['Defender'] || {}
  products = Array(av_status['Products'])
  # productState values the STIG identifies as active (up to date / out of date) are maintained in av_active_product_states
  active_products = products.select do |product|
    input('av_approved_software').include?(product['displayName']) &&
      input('av_active_product_states').include?(product['productState'].to_i)
  end

  describe.one do
    describe 'Microsoft Defender Antivirus (Get-MpComputerStatus)' do
      it 'is the primary antivirus (AMRunningMode Normal) with real-time protection enabled' do
        expect(defender['AMRunningMode']).to cmp 'Normal'
        expect(defender['RealTimeProtectionEnabled']).to cmp true
      end
    end
    describe "Approved and active antivirus registered with Windows Security Center (found: #{products.map { |p| "#{p['displayName']} [#{p['productState']}]" }.join(', ')})" do
      subject { active_products }
      it { should_not be_empty }
    end
  end
end
