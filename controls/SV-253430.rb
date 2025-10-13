control 'SV-253430' do
  title 'The US DOD CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systems.'
  desc 'To ensure users do not experience denial of service when performing certificate-based authentication to DOD websites due to the system chaining to a root other than DOD Root CAs, the US DOD CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificate Store. This requirement only applies to unclassified systems.'
  desc 'check', 'Verify the US DOD CCEB Interoperability Root CA cross-certificate is installed on unclassified systems as an Untrusted Certificate.

Run "PowerShell" as an administrator.

Execute the following command:

Get-ChildItem -Path Cert:Localmachine\\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint, NotAfter

If the following certificate "Subject", "Issuer", and "Thumbprint" information is not displayed, this is a finding. 

Subject: CN=DOD Root CA 3, OU=PKI, OU=DOD, O=U.S. Government, C=US
Issuer: CN=US DOD CCEB Interoperability Root CA 2, OU=PKI, OU=DOD, O=U.S. Government, C=US
Thumbprint: 9B74964506C7ED9138070D08D5F8B969866560C8
NotAfter: 7/18/2025 9:56:22 A

Alternately, use the Certificates MMC snap-in:

Run "MMC".

Select "File", then click "Add/Remove Snap-in".

Select "Certificates", then click "Add".

Select "Computer account", then click "Next".

Select "Local computer: (the computer this console is running on)", then click "Finish".

Click "OK".

Expand "Certificates" and navigate to Untrusted Certificates >> Certificates.

For each certificate with "US DOD CCEB Interoperability Root CA..." under "Issued By":

Right-click on the certificate and select "Open".

Select the "Details" tab.

Scroll to the bottom and select "Thumbprint".

If the certificate below is not listed or the value for the "Thumbprint" field is not as noted, this is a finding.

Subject: CN=DOD Root CA 3, OU=PKI, OU=DOD, O=U.S. Government, C=US
Issuer: CN=US DOD CCEB Interoperability Root CA 2, OU=PKI, OU=DOD, O=U.S. Government, C=US
Thumbprint: Thumbprint: 9B74964506C7ED9138070D08D5F8B969866560C8
NotAfter: 7/18/2025 9:56:22 AM                                       
Subject: CN=DOD Root CA 6, OU=PKI, OU=DOD, O=U.S. Government, C=US
Issuer: CN=US DOD CCEB Interoperability Root CA 2, OU=PKI, OU=DOD, O=U.S. Government, C=US
Thumbprint: D471CA32F7A692CE6CBB6196BD3377FE4DBCD106
NotAfter: 7/18/2026 9:56:22 AM'
  desc 'fix', 'Install the US DOD CCEB Interoperability Root CA cross-certificate on unclassified systems.

Issued To - Issued By - Thumbprint
9B74964506C7ED9138070D08D5F8B969866560C8
NotAfter: 7/18/2025 9:56:22 AM                                         
Issued To: DOD Root CA 6
Issued By: US DOD CCEB Interoperability Root CA 2
Thumbprint: D471CA32F7A692CE6CBB6196BD3377FE4DBCD106
NotAfter: 7/18/2026 

The certificates can be installed using the InstallRoot tool. The tool and user guide are available on Cyber Exchange at https://cyber.mil/pki-pke/tools-configuration-files. Certificate bundles published by the PKI can be found at https://crl.gds.disa.mil/.'
  impact 0.5
  tag check_id: 'C-56883r1081056_chk'
  tag severity: 'medium'
  tag gid: 'V-253430'
  tag rid: 'SV-253430r1081058_rule'
  tag stig_id: 'WN11-PK-000020'
  tag gtitle: 'SRG-OS-000403-GPOS-00182'
  tag fix_id: 'F-56833r1081057_fix'
  tag 'documentable'
  tag legacy: ['SV-78079', 'V-63589']
  tag cci: ['CCI-000185', 'CCI-002470']
  tag nist: ['IA-5 (2) (b) (1)', 'SC-23 (5)']

  dod_cceb_certificates = JSON.parse(input('dod_cceb_certificates').to_json)

  if input('sensitive_system') == 'true'
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  else
    query = json({ command: 'Get-ChildItem -Path Cert:Localmachine\\\\disallowed | Where {$_.Issuer -Like "*DoD CCEB Interoperability*" -and $_.Subject -Like "*DoD*"} | Select Subject, Issuer, Thumbprint, @{Name=\'NotAfter\';Expression={"{0:dddd, MMMM dd, yyyy}" -f [datetime]$_.NotAfter}} | ConvertTo-Json' })
    describe 'The DoD CCEB Interoperability CA cross-certificates installed' do
      subject { query.params }
      it { should be_in dod_cceb_certificates }
    end
  end
end
