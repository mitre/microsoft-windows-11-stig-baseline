control 'SV-253338' do
  title "The security event log size must be configured to a value that holds at least one week's worth of audit records."
  desc 'Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel. System administrators (SAs) must monitor the volume of security event audit records and increase the registry value for the log size as needed.'
  desc 'check', "If the system is configured to send audit records directly to an audit server, this requirement is not applicable. This must be documented with the information system security officer (ISSO).

The registry configuration setting below must be set (at least) to a value equal to the size needed to contain one week's worth of audit records in the security event log. The value used below is an example that assumes a typical week’s log size of 5GB.

If the following registry value does not exist or is not configured as specified, this is a finding:

Note: The following registry entry is an example; the value must equal at least one week's worth of records.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security\\

Value Name: MaxSize

Value Type: REG_DWORD
Value:0x49960800 (5120000) (or greater)"
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> Security >> "Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of a value that will contain one week of audit records or greater.

If the system is configured to send audit records directly to an audit server, this must be documented with the ISSO.'
  impact 0.5
  tag check_id: 'C-56791r1186373_chk'
  tag severity: 'medium'
  tag gid: 'V-253338'
  tag rid: 'SV-253338r1186375_rule'
  tag stig_id: 'WN11-AU-000505'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-56741r1186374_fix'
  tag 'documentable'
  tag legacy: ['V-63523', 'SV-78013']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security') do
    it { should have_property 'MaxSize' }
    its('MaxSize') { should be >= input('max_security_event_log_size') }
  end
end
