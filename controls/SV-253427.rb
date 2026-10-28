control 'SV-253427' do
  title 'The DoW Root CA certificates must be installed in the Trusted Root Store.'
  desc 'To ensure secure DoW websites and DoW-signed code are properly validated, the system must trust the DoW Root Certificate Authorities (CAs). The DoW root certificates will ensure that the trust chain is established for server certificates issued from the DoW CAs.'
  desc 'check', 'Verify the DoW Root CA certificates are installed as Trusted Root Certification Authorities.

The certificates referenced below apply to unclassified systems; refer to PKE documentation for other networks.

Run "PowerShell" as an administrator.

Execute the following command:

Get-ChildItem -Path Cert:Localmachine\\root | Where Subject -Like "*DoD*" | FL Subject, NotAfter

If valid DoW Root CA certificates (such as those below) are not displayed, this is a finding. 

Note: The Common Names (CN) below are examples. Verify the "CN" displayed is a DoW Root CA and is not expired. 

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
NotAfter: 12/30/2029

Subject: CN=DoD Root CA 5, OU=PKI, OU=DoD, O=U.S. Government, C=US
NotAfter: 6/14/2041

Subject: CN=DoD Root CA 6 OU=PKI, OU=DoD, O=U.S. Government, C=US
NotAfter: 1/24/2053

Alternately, use the Certificates MMC snap-in:

Run "MMC".

Select "File" and "Add/Remove Snap-in".

Select "Certificates" and click "Add".

Select "Computer account" and click "Next".

Select "Local computer: (the computer this console is running on)" and click "Finish".

Click "OK".

Expand "Certificates" and navigate to Trusted Root Certification Authorities >> Certificates.

For each of the DoW Root CA certificates listed:

Right-click on the certificate and select "Open".

Select the "Details" tab.

Verify the Expiration Date is a future date.

Scroll to the bottom and select "Subject".

If valid (unexpired) DoW Root CA certificates (such as those below) are not listed, this is a finding.

DoD Root CA 3
DoD Root CA 5 
DoD Root CA 6'
  desc 'fix', 'Install valid (unexpired) DoW Root CA certificates.

The list below is not to be treated as exhaustive. The STIG should not be used as a definitive resource for the organizationally approved certificates for the systems.

DoD Root CA 3
DoD Root CA 5 
DoD Root CA 6

The InstallRoot tool is available on Cyber Exchange at https://cyber.mil/pki-pke/tools-configuration-files. Certificate bundles published by the PKI can be found at https://crl.gds.disa.mil/.'
  impact 0.5
  tag check_id: 'C-56880r1256654_chk'
  tag severity: 'medium'
  tag gid: 'V-253427'
  tag rid: 'SV-253427r1256656_rule'
  tag stig_id: 'WN11-PK-000005'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-56830r1256655_fix'
  tag 'documentable'
  tag legacy: ['V-63579', 'SV-78069']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']

  if input('sensitive_system') == 'true'
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  else
    certificates = json(command: <<~PS).params
      $certs = Get-ChildItem -Path Cert:\\LocalMachine\\Root | Where-Object { $_.Subject -like '*DoD*' } |
        Select-Object Subject, @{ n = 'NotAfter'; e = { $_.NotAfter.ToString('yyyy-MM-dd') } }, @{ n = 'Expired'; e = { $_.NotAfter -lt (Get-Date) } }
      ConvertTo-Json -InputObject @($certs)
    PS

    input('dod_root_ca_cns').each do |cn|
      valid_certificates = certificates.select { |cert| cert['Subject'] =~ /CN=#{Regexp.escape(cn)}(,|\s|$)/ && cert['Expired'] == false }
      describe "A valid (unexpired) #{cn} certificate in the Trusted Root Certification Authorities store" do
        subject { valid_certificates.map { |cert| "#{cert['Subject']} (NotAfter: #{cert['NotAfter']})" } }
        it { should_not be_empty }
      end
    end
  end
end
