control 'SV-253428' do
  title 'The External Root CA certificates must be installed in the Trusted Root Store on unclassified systems.'
  desc 'To ensure secure websites protected with External Certificate Authority (ECA) server certificates are properly validated, the system must trust the ECA Root CAs. The ECA root certificates will ensure the trust chain is established for server certificates issued from the External CAs. This requirement applies only to unclassified systems.'
  desc 'check', 'Verify the ECA Root CA certificates are installed on unclassified systems as Trusted Root Certification Authorities.

Run "PowerShell" as an administrator.

Execute the following command:

Get-ChildItem -Path Cert:Localmachine\\root | Where Subject -Like "*ECA*" | FL Subject, NotAfter

If valid ECA Root CA certificates (such as those below) are not displayed, this is a finding. 

Note: The Common Names (CN) below are examples. Verify the "CN" displayed (ECA Root CA) is not expired. As of this writing, ECA Root CA 4 and ECA Root 5 are valid (among others).

Subject: CN=ECA Root CA 4, OU=ECA, O=U.S. Government, C=US
Subject: CN=ECA Root CA 5, OU=ECA, O=U.S. Government, C=US

Alternately, use the Certificates MMC snap-in:

Run "MMC".

Select "File" and "Add/Remove Snap-in".

Select "Certificates" and click "Add".

Select "Computer account" and click "Next".

Select "Local computer: (the computer this console is running on)" and click "Finish".

Click "OK".

Expand "Certificates" and navigate to Trusted Root Certification Authorities >> Certificates.

For each ECA Root CA certificate displayed:

Right-click on the certificate and select "Open".

Select the "Details" tab.

Verify the Expiration Date is a future date.

Scroll to the bottom and select "Subject".

If any of the certificates listed do not include "ECA Root CA" in the name or are expired, this is a finding.

Note: This should not be relied upon as a complete list of possible ECA Root CA certificates.

ECA Root CA 4
ECA Root CA 5'
  desc 'fix', 'Install valid (unexpired) ECA Root CA certificates on unclassified systems. 

The list below is not to be treated as exhaustive. The STIG should not be used as a definitive resource for the organizationally approved certificates for the systems.

ECA Root CA 4
ECA Root CA 5

The InstallRoot tool is available on Cyber Exchange at https://cyber.mil/pki-pke/tools-configuration-files. Certificate bundles published by the PKI can be found at https://crl.gds.disa.mil/.'
  impact 0.5
  tag check_id: 'C-56881r1256657_chk'
  tag severity: 'medium'
  tag gid: 'V-253428'
  tag rid: 'SV-253428r1256659_rule'
  tag stig_id: 'WN11-PK-000010'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-56831r1256658_fix'
  tag 'documentable'
  tag legacy: ['V-63583', 'SV-78073']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']

  if input('sensitive_system') == 'true'
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  else
    certificates = json(command: <<~PS).params
      $certs = Get-ChildItem -Path Cert:\\LocalMachine\\Root | Where-Object { $_.Subject -like '*ECA*' } |
        Select-Object Subject, @{ n = 'NotAfter'; e = { $_.NotAfter.ToString('yyyy-MM-dd') } }, @{ n = 'Expired'; e = { $_.NotAfter -lt (Get-Date) } }
      ConvertTo-Json -InputObject @($certs)
    PS

    describe 'ECA Root CA certificates in the Trusted Root Certification Authorities store' do
      subject { certificates.select { |cert| cert['Subject'] =~ /CN=ECA Root CA/ && cert['Expired'] == false } }
      it { should_not be_empty }
    end
    certificates.each do |cert|
      describe "Certificate #{cert['Subject']} (NotAfter: #{cert['NotAfter']})" do
        it 'is an ECA Root CA certificate' do
          expect(cert['Subject']).to match(/CN=ECA Root CA/)
        end
        it 'is not expired' do
          expect(cert['Expired']).to eq false
        end
      end
    end
  end
end
