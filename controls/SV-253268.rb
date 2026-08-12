control 'SV-253268' do
  title 'Unused accounts must be disabled or removed from the system after 35 days of inactivity.'
  desc 'Outdated or unused accounts provide penetration points that may go undetected. Inactive accounts must be deleted if no longer necessary or, if still required, disable until needed.'
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
For example: User1  10/31/2015  5:49:56  AM  True

Review the list to determine the finding validity for each account reported.

Exclude the following accounts:
Built-in administrator account (Disabled, SID ending in 500)
Built-in guest account (Disabled, SID ending in 501)
Built-in DefaultAccount (Disabled, SID ending in 503)
Local administrator account

If any enabled accounts have not been logged on to within the past 35 days, this is a finding.

Inactive accounts that have been reviewed and deemed to be required must be documented with the information system security officer (ISSO).)
  desc 'fix', 'Review local accounts and verify their necessity. Disable or delete any active accounts that have not been used in the last 35 days.'
  impact 0.3
  tag check_id: 'C-56721r997867_chk'
  tag severity: 'low'
  tag gid: 'V-253268'
  tag rid: 'SV-253268r1051039_rule'
  tag stig_id: 'WN11-00-000065'
  tag gtitle: 'SRG-OS-000468-GPOS-00212'
  tag fix_id: 'F-56671r828887_fix'
  tag 'documentable'
  tag legacy: ['V-63359', 'SV-77849']
  tag cci: ['CCI-003627', 'CCI-000795', 'CCI-000172']
  tag nist: ['AC-2 (3) (a)', 'IA-4 e', 'AU-12 c']

  # Simplified check, Get-LocalUser
  # Where account is enabled, and not a built-in system account
  # Where LastLogon exists, and last logon is more than 35 days ago

  users = powershell(<<~PS)
    $threshold = (Get-Date).AddDays(-35)
    
    Get-LocalUser |
      Where-Object { $_.Enabled -eq $true -and $_.SID -notlike '*-500' -and $_.SID -notlike '*-501' -and $_.SID -notlike '*-503' } |
      Where-Object { $_.LastLogon -and $_.LastLogon -lt $threshold } |
      Select-Object Name, SID, LastLogon
  PS

  describe users do
    its('exit_status') { should eq 0 }
    its('stdout.strip') { should eq '' }  # pass if no stale users
  end
end