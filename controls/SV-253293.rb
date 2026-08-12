control 'SV-253293' do
  title 'The system must notify the user when a Bluetooth device attempts to connect.'
  desc 'If not configured properly, Bluetooth may allow rogue devices to communicate with a system. If a rogue device is paired with a system, there is potential for sensitive information to be compromised.'
  desc 'check', 'This is NA if the system does not have Bluetooth, or if Bluetooth is turned off per the organizations policy.

Search for "Bluetooth".
View Bluetooth Settings.
Select "More Bluetooth Options"
If "Alert me when a new Bluetooth device wants to connect" is not checked, this is a finding.'
  desc 'fix', 'Configure Bluetooth to notify users if devices attempt to connect.
View Bluetooth Settings.
Ensure "Alert me when a new Bluetooth device wants to connect" is checked.'
  impact 0.5
  tag check_id: 'C-56746r828961_chk'
  tag severity: 'medium'
  tag gid: 'V-253293'
  tag rid: 'SV-253293r991589_rule'
  tag stig_id: 'WN11-00-000230'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56696r828962_fix'
  tag 'documentable'
  tag legacy: ['SV-87407', 'V-72769']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

pnp = <<~POWERSHELL
    $bt = @(Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' })
    $bt.Count
  POWERSHELL

  bt_count = powershell(pnp).stdout.to_i

  # 2) No Bluetooth devices -> control passes
  if bt_count == 0
    describe 'Bluetooth presence check' do
      it 'has no Bluetooth devices present' do
        expect(bt_count).to eq 0
      end
    end

  else
    bt_notify_key = registry_key('HKEY_CURRENT_USER\\Software\\Microsoft\\BluetoothAuthenticationAgent')

    describe 'Bluetooth connection request notifications (current user)' do
      subject { bt_notify_key }
    end

    describe.one do
      describe bt_notify_key do
        it 'is not configured (key missing), which is treated as compliant as this is the default Windows Behavior' do
          expect(bt_notify_key.exists?).to eq false
        end
      end

      describe bt_notify_key do
        its('AcceptIncomingRequests') { should cmp 1 }
      end
    end
  end
end