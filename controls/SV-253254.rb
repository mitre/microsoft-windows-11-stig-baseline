control 'SV-253254' do
  title 'Domain-joined systems must use Windows 11 Enterprise Edition 64-bit version.'
  desc 'Features such as Credential Guard use virtualization-based security to protect information that could be used in credential theft attacks if compromised. There are a number of system requirements that must be met in order for Credential Guard to be configured and enabled properly. Virtualization-based security and Credential Guard are only available with Windows 11 Enterprise 64-bit version.'
  desc 'check', 'Verify domain-joined systems are using Windows 11 Enterprise Edition 64-bit version.

For standalone systems, this is NA.

Open "Settings".

Select "System", then "About".

If "Edition" is not "Windows 11 Enterprise", this is a finding.

If "System type" is not "64-bit operating system...", this is a finding.'
  desc 'fix', 'Use Windows 11 Enterprise 64-bit version for domain-joined systems.'
  impact 0.5
  tag check_id: 'C-56707r828844_chk'
  tag severity: 'medium'
  tag gid: 'V-253254'
  tag rid: 'SV-253254r991589_rule'
  tag stig_id: 'WN11-00-000005'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56657r828845_fix'
  tag 'documentable'
  tag legacy: ['V-63319', 'SV-77809']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  is_domain = command('(gwmi win32_computersystem).partofdomain').stdout.strip == 'True'
  if is_domain
    describe os.arch do
      it { should eq 'x86_64' }
    end
    describe os.name do
      it { should eq 'windows_11_enterprise' }
    end
  else
    impact 0.0
    describe 'This system is not joined to a domain, therefore this control is Not Applicable' do
      skip 'This system is not joined to a domain, therefore this control is Not Applicable'
    end
  end
end
