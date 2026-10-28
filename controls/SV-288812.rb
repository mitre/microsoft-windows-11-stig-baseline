control 'SV-288812' do
  title 'Unused accounts must be disabled or removed from the system after 35 days of inactivity.'
  desc 'Outdated or unused accounts provide penetration points that may go undetected. Inactive accounts must be disabled until needed (if still required), or deleted if no longer necessary.

'
  desc 'check', %q(Run "PowerShell".
Copy the lines below to the PowerShell window and enter.

"([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
  $user = ([ADSI]$_.Path)
  $lastLogin = $user.Properties.LastLogin.Value
  $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
  if ($lastLogin -eq $null) {
   $lastLogin = 'Never'
  }
  Write-Host $user.Name $lastLogin $enabled 
}"

This will return a list of local accounts with the account name, last logon, and if the account is enabled (True/False).
For example: User1 10/31/2025 5:49:56 AM True

Review the list to determine the finding validity for each account reported.

Exclude the following accounts:
Built-in administrator account (SID ending in 500)
Built-in guest account (SID ending in 501)
Built-in DefaultAccount (SID ending in 503)
Local administrator account

If any enabled accounts have not been logged on to within the past 35 days, this is a finding.

Inactive accounts that have been reviewed and deemed to be required must be documented with the information system security officer (ISSO).)
  desc 'fix', 'Review local accounts and verify their necessity. Disable or delete any active accounts that have not been used in the last 35 days.'
  impact 0.3
  tag check_id: 'C-93501r1260010_chk'
  tag severity: 'low'
  tag gid: 'V-288812'
  tag rid: 'SV-288812r1260011_rule'
  tag stig_id: 'WN11-00-000065'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-93406r1259971_fix'
  tag satisfies: 'SRG-OS-000118-GPOS-00060'
  tag 'documentable'
  tag cci: ['CCI-000017']
  tag nist: ['AC-2 (3) (d)']

  # Enabled local accounts that have not logged on within max_inactive_days (accounts that have never logged on are included).
  # Excluded per the check: built-in Administrator (-500), Guest (-501), DefaultAccount (-503)
  # and local administrator accounts (local members of the Administrators group, S-1-5-32-544).
  inactive_accounts = json(command: <<~PS).params
    $threshold = (Get-Date).AddDays(-#{input('max_inactive_days')})
    $admins = @(Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-544'" |
      Get-CimAssociatedInstance -Association Win32_GroupUser |
      Where-Object { $_.LocalAccount } | ForEach-Object { $_.SID })
    $accounts = Get-LocalUser |
      Where-Object { $_.Enabled -and $_.SID.Value -notmatch '-(500|501|503)$' -and $admins -notcontains $_.SID.Value } |
      Where-Object { -not $_.LastLogon -or $_.LastLogon -lt $threshold } |
      Select-Object Name, @{ n = 'LastLogon'; e = { if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd') } else { 'Never' } } }
    ConvertTo-Json -InputObject @($accounts)
  PS

  describe "Enabled local accounts that have not logged on within the past #{input('max_inactive_days')} days" do
    subject { inactive_accounts.map { |account| "#{account['Name']} (last logon: #{account['LastLogon']})" } }
    it { should be_empty }
  end
end
