control 'SV-253476' do
  title 'Passwords for enabled local Administrator accounts must be changed at least every 60 days.'
  desc 'The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password. A local Administrator account is not generally used and its password may not be changed as frequently as necessary. Changing the password for enabled Administrator accounts on a regular basis will limit its exposure.

Windows LAPS must be used to change the built-in Administrator account password.'
  desc 'check', 'If there are no enabled local Administrator accounts, this is Not Applicable.

Review the password last set date for the enabled local Administrator account.

On the standalone or domain-joined workstation:

Open "PowerShell".

Enter "Get-LocalUser -Name * | Select-Object *".

If the "PasswordLastSet" date is greater than "60" days old for the local Administrator account for administering the computer/domain, this is a finding.

Verify LAPS is configured and operational.

Navigate to Local Computer Policy >> Computer Configuration >> Administrative Templates >> System >> LAPS >> Password Settings >> Set to enabled. Password Complexity, large letters + small letters + numbers + special, Password Length 14, Password Age 60. If not configured as shown, this is a finding.

Verify LAPS Operational logs >> Event Viewer >> Applications and Services Logs >> Microsoft >> Windows >> LAPS >> Operational. Verify LAPS policy process is completing. If it is not, this is a finding.'
  desc 'fix', 'Change the enabled local Administrator account password at least every 60 days.

Windows LAPS must be used to change the built-in Administrator account password. Domain-joined and nondomain-joined systems can configure this to occur more frequently. LAPS will change the password every 30 days by default.

More information is available at:
https://techcommunity.microsoft.com/t5/windows-it-pro-blog/by-popular-demand-windows-laps-available-now/ba-p/3788747
https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview#windows-laps-supported-platforms-and-azure-ad-laps-preview-status'
  impact 0.5
  tag check_id: 'C-56929r1016367_chk'
  tag severity: 'medium'
  tag gid: 'V-253476'
  tag rid: 'SV-253476r1051060_rule'
  tag stig_id: 'WN11-SO-000280'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-56879r997891_fix'
  tag 'documentable'
  tag cci: ['CCI-004066', 'CCI-000199']
  tag nist: ['IA-5 (1) (h)', 'IA-5 (1) (d)']

  only_if('Control is Not Applicable when no local Administrator account is enabled') do
    powershell('(Get-LocalUser -Name Administrator).Enabled').stdout.strip == 'True'
  end

  describe 'Local Administrator account password last changed within the past 60 days' do
    subject do
      powershell('[datetime]::Now.AddDays(-60) -lt (Get-LocalUser -Name Administrator).PasswordLastSet').stdout.strip
    end

    it { should cmp 'True' }
  end

  describe 'Windows LAPS registry setting' do
    subject { registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS') }

    it 'has PasswordComplexity set to 4 (uppercase, lowercase, numbers, special)' do
      expect(subject['PasswordComplexity']).to cmp 4
    end

    it 'has PasswordLength set to 14 characters' do
      expect(subject['PasswordLength']).to cmp 14
    end

    it 'has PasswordAgeDays set to 60 days' do
      expect(subject['PasswordAgeDays']).to cmp 60
    end
  end

  describe 'LAPS policy processing event succeeded' do
    subject { powershell("(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-LAPS/Operational'; Id=10004} -MaxEvents 1).Count").stdout.to_i }

    it 'verifies LAPS policy process is completing' do
      expect(subject).to be > 0
    end
  end
end
