control 'SV-253272' do
  title 'Standard local user accounts must not exist on a system in a domain.'
  desc 'To minimize potential points of attack, local user accounts, other than built-in accounts and local administrator accounts, must not exist on a workstation in a domain. Users must log on to workstations in a domain with their domain accounts.'
  desc 'check', 'Run "Computer Management".

Navigate to System Tools >> Local Users and Groups >> Users.

If local users other than the accounts listed below exist on a workstation in a domain, this is a finding. 

The accounts listed assumes a system is joined to a domain and thus (per best practice), the local default accounts have been disabled.

For standalone or nondomain-joined systems, this is Not Applicable.

Built-in guest account (SID ending in 501)
Built-in DefaultAccount (SID ending in 503)
Built-in defaultuser0 (*SID unique per workstation)
Built-in WDAGUtilityAccount (SID ending in 504)
Local administrator account(s)

* Note: The SID for defaultuser0 is machine-specific and immutable (cannot be changed). It will differ per Windows installation.

Some of the built-in accounts may not exist on a system, depending on the Windows 11 version.
Refer to WN11-SO-000280 for requirement/guidance in use of Windows LAPS to manage the built-in administrator account password.'
  desc 'fix', 'Limit local user accounts on domain-joined systems. Remove any unauthorized local accounts.'
  impact 0.3
  tag check_id: 'C-56725r1259979_chk'
  tag severity: 'low'
  tag gid: 'V-253272'
  tag rid: 'SV-253272r1268251_rule'
  tag stig_id: 'WN11-00-000085'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56675r828899_fix'
  tag 'documentable'
  tag legacy: ['SV-77857', 'V-63367']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  join_type = inspec.powershell(<<~EOH).stdout.strip
    $dsreg = & "$env:windir\\system32\\dsregcmd.exe" /status 2>$null
    $azure = ($dsreg | Select-String -Pattern '^\\s*AzureAdJoined\\s*:\\s*').ToString().Split(':')[-1].Trim()
    $domain = ($dsreg | Select-String -Pattern '^\\s*DomainJoined\\s*:\\s*').ToString().Split(':')[-1].Trim()

    if ($azure -eq 'YES' -and $domain -eq 'YES') { 'Hybrid' }
    elseif ($azure -eq 'YES') { 'AzureAD' }
    elseif ($domain -eq 'YES') { 'Domain' }
    else { 'None' }
    EOH

  if join_type == 'None'
    impact 0.0
    describe 'The system is not a member of a domain' do
      skip 'Control is Not Applicable for standalone/Azure AD-only systems.'
    end
  else
    # Local accounts, flagged when they are local members of the Administrators group (S-1-5-32-544)
    local_users = json(command: <<~PS).params
      $admins = @(Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-544'" |
        Get-CimAssociatedInstance -Association Win32_GroupUser |
        Where-Object { $_.LocalAccount } | ForEach-Object { $_.SID })
      $users = Get-LocalUser | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; SID = $_.SID.Value; Enabled = $_.Enabled; Administrator = $admins -contains $_.SID.Value }
      }
      ConvertTo-Json -InputObject @($users)
    PS

    # Built-in Guest (-501), DefaultAccount (-503), WDAGUtilityAccount (-504) and defaultuser0 (machine-specific SID)
    built_in = local_users.select { |user| user['SID'] =~ /-(501|503|504)$/ || user['Name'] == 'defaultuser0' }
    other_users = local_users.reject { |user| built_in.include?(user) || user['Administrator'] }

    describe 'Local user accounts other than the built-in accounts and local administrator accounts' do
      subject { other_users.map { |user| user['Name'] } }
      it { should be_empty }
    end
    built_in.each do |user|
      describe "Built-in account #{user['Name']} needs to be disabled as part of security" do
        subject { user['Enabled'] }
        it { should eq false }
      end
    end
  end
end
