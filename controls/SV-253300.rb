control 'SV-253300' do
  title 'The password history must be configured to 24 passwords remembered.'
  desc 'A system is more vulnerable to unauthorized access when system users recycle the same password several times without being required to change a password to a unique password on a regularly scheduled basis. This enables users to effectively negate the purpose of mandating periodic password changes. The default value is 24 for Windows domain systems. DoW has determined this is the appropriate value for all Windows systems.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

For GPO-managed systems, navigate to:

Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

Or

For Intune-managed systems, navigate to:

HKLM:\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\DeviceLock!DevicePasswordHistory

If the value for "Enforce password history" is less than "24" passwords remembered, this is a finding.'
  desc 'fix', 'For GPO-managed systems:

Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> "Enforce password history" to "24" passwords remembered.

For Intune-managed systems:

Revise the Intune policy to set password history policy to "24" passwords remembered.'
  impact 0.5
  tag check_id: 'C-56753r1210192_chk'
  tag severity: 'medium'
  tag gid: 'V-253300'
  tag rid: 'SV-253300r1256653_rule'
  tag stig_id: 'WN11-AC-000020'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-56703r1256652_fix'
  tag 'documentable'
  tag legacy: ['V-63415', 'SV-77905']
  tag cci: ['CCI-004061']
  tag nist: ['IA-5 (1) (b)']

  pass_hist_size = input('pass_hist_size')

  # GPO-managed systems report the effective security policy; Intune-managed systems store DeviceLock CSP values in PolicyManager
  describe.one do
    describe security_policy do
      its('PasswordHistorySize') { should cmp >= pass_hist_size }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock') do
      it { should have_property 'DevicePasswordHistory' }
      its('DevicePasswordHistory') { should cmp >= pass_hist_size }
    end
  end
end
