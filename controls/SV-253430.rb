control 'SV-253430' do
  title 'The US DoW CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systems.'
  desc 'To ensure users do not experience denial of service when performing certificate-based authentication to DoW websites due to the system chaining to a root other than DoW Root CAs, the US DoW CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificate Store. This requirement only applies to unclassified systems.'
  desc 'check', %q(Verify the US DoW CCEB Interoperability Root CA cross-certificate is installed on unclassified systems as an Untrusted Certificate.

Run "PowerShell" as an administrator.

Execute the following command:

Get-ChildItem -Path Cert:Localmachine\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, NotAfter

If valid US DoW CCEB Interoperability Root CA certificates (such as those below) are not displayed, this is a finding. 

Note: The Common Names (CN) below are examples. Verify the "CN" displayed is a DoW CCEB Interoperability Root CA and is not expired.

Subject: CN= US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
NotAfter: 12/30/2030 

Alternately, use the Certificates MMC snap-in:

Run "MMC".

Select "File", then click "Add/Remove Snap-in".

Select "Certificates", then click "Add".

Select "Computer account", then click "Next".

Select "Local computer: (the computer this console is running on)", then click "Finish".

Click "OK".

Expand "Certificates" and navigate to Untrusted Certificates >> Certificates.

For each US DoW CCEB Interoperability Root CA certificate displayed:

Right-click on the certificate and select "Open".

Select the "Details" tab.

Scroll to the bottom and select "Subject".

If any of the certificates listed do not include "DoD Interoperability Root CA" in the name or are expired, this is a finding.

US DoD CCEB Interoperability Root CA 2                                  

Note: Interoperability cross certificates will have a different value (such as "...Root CA 6") in the 'Issued To'  field than in the 'Subject' and 'Issuer' fields.)
  desc 'fix', 'Install the US DoW CCEB Interoperability Root CA cross-certificate on unclassified systems.

The list below is not to be treated as exhaustive. The STIG should not be used as a definitive resource for the organizationally approved certificates for the systems.

US DOD CCEB Interoperability Root CA 2

The certificates can be installed using the InstallRoot tool. The tool and user guide are available on Cyber Exchange at https://cyber.mil/pki-pke/tools-configuration-files. Certificate bundles published by the PKI can be found at https://crl.gds.disa.mil/.'
  impact 0.5
  tag check_id: 'C-56883r1256663_chk'
  tag severity: 'medium'
  tag gid: 'V-253430'
  tag rid: 'SV-253430r1268247_rule'
  tag stig_id: 'WN11-PK-000020'
  tag gtitle: 'SRG-OS-000403-GPOS-00182'
  tag fix_id: 'F-56833r1256664_fix'
  tag 'documentable'
  tag legacy: ['SV-78079', 'V-63589']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']

  if input('sensitive_system') == 'true'
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  else
    certificates = json(command: <<~PS).params
      $certs = Get-ChildItem -Path Cert:\\LocalMachine\\Disallowed | Where-Object { $_.Issuer -like '*CCEB Interoperability*' } |
        Select-Object Subject, Issuer, @{ n = 'NotAfter'; e = { $_.NotAfter.ToString('yyyy-MM-dd') } }, @{ n = 'Expired'; e = { $_.NotAfter -lt (Get-Date) } }
      ConvertTo-Json -InputObject @($certs)
    PS

    describe 'US DoW CCEB Interoperability Root CA cross-certificates in the Untrusted Certificates store' do
      subject { certificates.select { |cert| cert['Expired'] == false } }
      it { should_not be_empty }
    end
    certificates.each do |cert|
      describe "Cross-certificate #{cert['Subject']} issued by #{cert['Issuer']} (NotAfter: #{cert['NotAfter']})" do
        subject { cert['Expired'] }
        it { should eq false }
      end
    end
  end
end
