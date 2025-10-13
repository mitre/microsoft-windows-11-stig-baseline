control 'SV-253470' do
  title 'Windows 11 must use multifactor authentication for local and network access to privileged and nonprivileged accounts.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged and nonprivileged functions is greatly increased.

All domain accounts must be enabled for multifactor authentication with the exception of local emergency accounts.

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include:

1) Something a user knows (e.g., password/PIN);
2) Something a user has (e.g., cryptographic identification device, token); and
3) Something a user is (e.g., biometric).

A privileged account is defined as an information system account with authorizations of a privileged user.

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet).

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network.

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'If the system is not a member of a domain, this is Not Applicable.

If all of the following settings exist and are populated, this is not a finding.

\\HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Calais\\Readers
\\HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards'
  desc 'fix', "For nondomain joined systems, configuring Windows Hello for sign-on options would be suggested based on the organization's needs and capabilities."
  impact 0.5
  tag check_id: 'C-56923r1106509_chk'
  tag severity: 'medium'
  tag gid: 'V-253470'
  tag rid: 'SV-253470r1106510_rule'
  tag stig_id: 'WN11-SO-000251'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-56873r890469_fix'
  tag satisfies: ['SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055']
  tag 'documentable'
  tag legacy: ['SV-111577', 'V-102627']
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']

  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip

  reader_script = <<-EOH
   (Get-Item 'Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Calais\\Readers').Property.Count
  EOH

  card_script = <<-EOH
   (Get-Item 'Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards').Property.Count
  EOH

  if is_domain == 'WORKGROUP'
    impact 0.0
    describe 'The system is not a member of a domain, control is NA' do
      skip 'The system is not a member of a domain, control is NA'
    end
  else

    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Calais\\Readers') do
      it { should exist }
    end

    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards') do
      it { should exist }
    end

    describe 'Registry key HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Calais\\Readers is populated' do
      subject { powershell(reader_script).stdout.strip.to_i }
      it { should be > 0 }
    end

    describe 'Registry key HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards is populated' do
      subject { powershell(card_script).stdout.strip.to_i }
      it { should be > 0 }
    end
  end
end
