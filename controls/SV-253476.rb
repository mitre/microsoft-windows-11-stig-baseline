control 'SV-253476' do
  title 'Passwords for enabled local Administrator accounts must be changed at least every 180 days.'
  desc 'The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password. A local Administrator account is not generally used and its password may not be changed as frequently as necessary. Changing the password for enabled Administrator accounts on a regular basis will limit their exposure.

Windows LAPS must be used to change the built-in Administrator account password. Operational limitations preventing the use of Windows Local Administrator Password Solution (LAPS) must be approved by the authorizing official (AO).'
  desc 'check', 'If there are no enabled local Administrator accounts, this is Not Applicable.

Use of an enabled built-in account without management by LAPS must be documented and supplied to the information system security manager (ISSM)/information system security officer (ISSO) for their risk acceptance. 

An alternative process to LAPS is acceptable if it is documented and produces evidence that passwords for Administrator accounts are changed at least every 180 days.

Review the password last set date for the enabled local Administrator account.

On the standalone or domain-joined workstation:

Open "PowerShell".

Enter "Get-LocalUser -Name * | Select-Object *".

If the "PasswordLastSet" date is greater than "180" days old for the local Administrator account for administering the computer/domain, this is a finding.

Verify LAPS is configured and operational. 

Navigate to Local Computer Policy >> Computer Configuration >> Administrative Templates >> System >> LAPS >> Password Settings >> Set to enabled. Password Complexity, large letters + small letters + numbers + special, Password Length 14, Password Age 180. If not configured as shown, this is a finding. 

Verify LAPS Operational logs >> Event Viewer >> Applications and Services Logs >> Microsoft >> Windows >> LAPS >> Operational. Verify LAPS policy process is completing. If it is not, this is a finding.'
  desc 'fix', 'Change the enabled local Administrator account password at least every 180 days. 

Windows LAPS must be used to change the built-in Administrator account password. Domain-joined and nondomain-joined systems can configure this to occur more frequently. LAPS will change the password every 30 days by default. 

Operational limitations preventing the use of LAPS must be approved by the AO.

More information is available at:
https://techcommunity.microsoft.com/t5/windows-it-pro-blog/by-popular-demand-windows-laps-available-now/ba-p/3788747
https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview#windows-laps-supported-platforms-and-azure-ad-laps-preview-status'
  impact 0.5
  tag check_id: 'C-56929r1259999_chk'
  tag severity: 'medium'
  tag gid: 'V-253476'
  tag rid: 'SV-253476r1268211_rule'
  tag stig_id: 'WN11-SO-000280'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-56879r1260000_fix'
  tag 'documentable'
  tag cci: ['CCI-004066', 'CCI-000199']
  tag nist: ['IA-5 (1) (h)', 'IA-5 (1) (d)']

  max_age = input('local_admin_pass_age')

  # The built-in Administrator account is identified by its well-known RID (500) since it may be renamed
  admin = json(command: <<~PS).params
    Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } |
      Select-Object Name, Enabled, @{ n = 'PasswordLastSetDays'; e = { if ($_.PasswordLastSet) { ((Get-Date) - $_.PasswordLastSet).Days } } } |
      ConvertTo-Json
  PS

  only_if('Control is Not Applicable when no local Administrator account is enabled') do
    admin['Enabled'] == true
  end

  join_type = inspec.powershell(<<~EOH).stdout.strip
    $dsreg = & "$env:windir\\system32\\dsregcmd.exe" /status 2>$null
    $azure = ($dsreg | Select-String -Pattern '^\\s*AzureAdJoined\\s*:\\s*').ToString().Split(':')[-1].Trim()
    $domain = ($dsreg | Select-String -Pattern '^\\s*DomainJoined\\s*:\\s*').ToString().Split(':')[-1].Trim()

    if ($azure -eq 'YES' -and $domain -eq 'YES') { 'Hybrid' }
    elseif ($azure -eq 'YES') { 'AzureAD' }
    elseif ($domain -eq 'YES') { 'Domain' }
    else { 'None' }
    EOH

  #Per MSFT Docs, Windows LAPS only supports Microsoft Entra joined or Active Directory joined devices
  if join_type == 'None'
    impact 0.0
    describe 'This system is not joined to EntraID or a domain, therefore this control is Not Applicable' do
      skip 'This system is not joined to EntraID or a domain, therefore this control is Not Applicable'
    end
  else
    describe "Local Administrator account #{admin['Name']} password last changed within the past #{max_age} days" do
      subject { admin['PasswordLastSetDays'] }
      it { should_not be_nil }
      it { should cmp <= max_age }
    end

    # Windows LAPS uses the first policy root (in this order) that contains any settings, and
    # applies the default value for any setting that root does not define.
    laps = json(command: <<~PS).params
      $roots = @(
        'HKLM:\\SOFTWARE\\Microsoft\\Policies\\LAPS',
        'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS',
        'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS\\Config'
      )
      $active = $roots | Where-Object { (Get-Item -LiteralPath $_ -ErrorAction SilentlyContinue).ValueCount -gt 0 } | Select-Object -First 1
      $policy = if ($active) { Get-ItemProperty -LiteralPath $active } else { $null }
      [pscustomobject]@{
        Root               = $active
        BackupDirectory    = $policy.BackupDirectory
        PasswordComplexity = $policy.PasswordComplexity
        PasswordLength     = $policy.PasswordLength
        PasswordAgeDays    = $policy.PasswordAgeDays
      } | ConvertTo-Json
    PS
    laps_defaults = { 'BackupDirectory' => 0, 'PasswordComplexity' => 4, 'PasswordLength' => 14, 'PasswordAgeDays' => 30 }
    laps_setting = ->(name) { laps[name].nil? ? laps_defaults[name] : laps[name] }

    describe "Windows LAPS policy (#{laps['Root'] || 'no policy configured'})" do
      it 'is configured' do
        expect(laps['Root']).not_to be_nil
      end
      it 'backs up the password to Microsoft Entra ID or Active Directory (BackupDirectory 1 or 2)' do
        expect(laps_setting.call('BackupDirectory')).to be_in [1, 2]
      end
      it 'has PasswordComplexity set to large letters + small letters + numbers + special characters (4 or 5)' do
        expect(laps_setting.call('PasswordComplexity')).to be_in [4, 5]
      end
      it 'has PasswordLength set to 14 characters or more' do
        expect(laps_setting.call('PasswordLength')).to cmp >= 14
      end
      it "has PasswordAgeDays set to #{max_age} days or less" do
        expect(laps_setting.call('PasswordAgeDays')).to cmp <= max_age
      end
    end

    describe 'LAPS policy processing event succeeded' do
      subject { powershell("(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-LAPS/Operational'; Id=10004} -MaxEvents 1).Count").stdout.to_i }

      it 'verifies LAPS policy process is completing' do
        expect(subject).to be > 0
      end
    end
  end
end
