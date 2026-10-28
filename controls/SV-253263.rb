control 'SV-253263' do
  title 'Windows 11 systems must be maintained at a supported servicing level.'
  desc %q(Windows 11 is maintained by Microsoft at servicing levels for specific periods of time to support Windows as a Service. An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software. Systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities which leaves them subject to exploitation. 

The type of servicing channel used will determine the frequency of OS updates and length of support. Under the General Availability Channel (GAC), Microsoft releases one major feature update per year (typically in the second half of the calendar year, e.g., Version 24H2). For Windows 11 Enterprise, each annual GAC release receives 36 months of support. The Long-Term Servicing Channel (LTSC) is designed for highly regulated, air-gapped, or mission-critical military/tactical environments. Microsoft releases a new LTSC version approximately every 2 to 3 years. Windows 11 Enterprise LTSC receives five years of lifecycle support (quality and security updates only; no feature updates).

Many Microsoft software updates and fixes are regularly combined into a single package (called a service pack) that is made available for installation. Both the Mainstream Support and Extended Support phases for software require a product's supported service pack to be installed to continue to receive full support. Microsoft publishes specific support timelines for a previous service pack when the new service pack is released. Systems must install a fully supported service pack to ensure they are on the latest and most secure version of their product.)
  desc 'check', %q(1. Determine your Windows 11 OS version.
a. Run "winver.exe".
The "About Windows" dialog box will display the system's version and OS build. For example, "Microsoft  Windows 11 Version 24H2 (OS Build 26100.8875)". Record the numbers observed.

2. Determine the system's latest installed security patch.
a. Open "PowerShell" with elevated privileges (run as administrator).
b. Enter the following:
Get-HotFix -Description "Security Update" 
c. Record the "InstalledOn" date and the KB numbers listed under the "HotFixID" column in the resulting display.

3. Determine Microsoft's Support timeframe for the system's Windows 11 OS version.
a. Access Microsoft's Lifecycle & Build History website at https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information. 
b. Review the table listing the "Windows 11 current versions by servicing option" to find the end-of-support date corresponding to the system's OS version. This date marks the official deadline after which Microsoft stops providing software support (or security updates) for that operating system version. The Windows 11 current versions are categorized by servicing option. For example, (as of Aug 2026) under the General Availability Channel for Enterprise version 25H, the last date for (support) updates is 2028-10-10, and the latest build is 26200.9168. Similar data is provided for the Enterprise LTSC releases. 
c. Review (on the same page) a table listing "Windows 11 release history" data for OS hotpatch updates. Compare the system's OS build and KB # (from step 1 and 2) with those listed to determine how many (if any) newer patches are available for the system's OS version. It is strongly recommended that the latest security patch be installed, unless there is a valid operational reason to delay installing it.

If the end-of-support date for the system's OS version (from step 3b) is a past date, this is a finding.)
  desc 'fix', "Determine if the end-of-support date for the system's OS build (from Microsoft's Windows 11 release history website) is a past date. 
If the end-of-support date for the system's OS build is in the past, perform an update to an OS build whose end-of-support date is a future date."
  impact 0.7
  tag check_id: 'C-56716r1259973_chk'
  tag severity: 'high'
  tag gid: 'V-253263'
  tag rid: 'SV-253263r1268251_rule'
  tag stig_id: 'WN11-00-000040'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56666r1259974_fix'
  tag 'documentable'
  tag legacy: ['V-63349', 'SV-77839']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # End-of-servicing dates are maintained in the windows_11_end_of_servicing input, sourced from
  # https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information
  os_info = json(command: 'Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, BuildNumber | ConvertTo-Json').params
  caption = os_info['Caption'].to_s
  build = os_info['BuildNumber'].to_s
  # InSpec symbolizes Hash input keys; normalize them to strings for lookup
  releases = input('windows_11_end_of_servicing').to_h { |os_build, options| [os_build.to_s, options.to_h.transform_keys(&:to_s)] }
  release = releases[build]

  # Map the edition to the servicing option columns used on the release information page
  servicing_option = if caption =~ /LTSC/i
                       caption =~ /IoT/i ? 'iot_ltsc' : 'ltsc'
                     elsif caption =~ /\b(Home|Pro)\b/i
                       'home_pro'
                     elsif caption =~ /Enterprise|Education/i
                       'enterprise'
                     else
                       'home_pro'
                     end
  end_of_servicing = release.nil? ? nil : release[servicing_option]

  describe "#{caption} (OS build #{build})" do
    it 'is a Windows 11 version listed in the Windows 11 release information' do
      expect(release).not_to be_nil, "OS build #{build} is not a currently serviced Windows 11 version"
    end
    it "has an end-of-servicing date that has not passed (#{servicing_option}: #{end_of_servicing || 'end of updates'})" do
      expect(end_of_servicing.to_s).to be >= Time.now.strftime('%Y-%m-%d')
    end
  end
end
