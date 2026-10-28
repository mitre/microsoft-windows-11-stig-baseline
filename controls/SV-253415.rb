control 'SV-253415' do
  title 'PowerShell Transcription must be enabled on Windows 11.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Enabling PowerShell Transcription will record detailed information from the processing of PowerShell commands and scripts. This can provide additional detail when malware has run on a system.'
  desc 'check', %q(If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\

Value Name: EnableTranscripting

Value Type: REG_DWORD
Value: 1

The location used for log storage must be a write-only, restricted directory (preferably a network share) that security personnel can access. The registry value setting for "Transcript output directory" is set by the GPO to "C:\ProgramData\PS_Transcript". That directory allows Read, Modify, and Delete access by standard (nonprivileged) user accounts. Either a different directory that has appropriate access permissions must be configured (see Fix text), or the permissions for the existing Transcript output directory must be configured appropriately.

If the directory used to store the PowerShell transcription log files (Transcript output directory) permits read or modify access by nonprivileged users, this is a finding.

If the output directory set by the GPO is preferred, the access permissions must be revised to ensure the PowerShell Transcription log files are accessible only to the Administrator and System accounts. 

To review permissions of the output directory, enter the following commands. 
Open "Command Prompt (Admin)".

[Enter "icacls" followed by the directory configured to store PowerShell Transcription logs:]
icacls C:\ProgramData\PS_Transcript

If log files currently reside in the output directory, issue the following:
icacls C:\ProgramData\PS_Transcript\*.*

The results must be displayed as below:
NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
BUILTIN\Administrators:(OI)(CI)(IO)(F)
*NT AUTHORITY\Authenticated Users:(OI)(CI)(WD,AD)
*BUILTIN\Users:(OI)(CI)(WD,AD)
*Note: The standard user accounts may differ based on the system's purpose/role and Active Directory structure.

If the directory used to store PowerShell Transcription logs is not configured to provide Full Control access to Administrative and System accounts while permitting write-only access for standard user accounts, this is a finding.)
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows PowerShell >> "Turn on PowerShell Transcription" to "Enabled".

If a centralized (versus local) Transcript output directory is preferred, configure the Transcript output directory to point to a Central Log Server or another secure location to prevent user Read, Modify, and Delete access by nonprivileged accounts.

Ensure the selected directory is write-only with Full Control access granted to Administrator and System accounts.

Enter the following registry value:
Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription
*Value Name: OutputDirectory
Value Type: REG_SZ (String Value)

* Note: "OutputDirectory" value should be: "[custom directory path (e.g., I:\\UserX_PowerShellTranscripts)]"

If the folder configured (in the registry) as the Transcript output directory is not configured to provide Full Control access to Administrative and System accounts, while permitting WD, AD access for standard user accounts, issue the following commands: 
Open "Command Prompt (Admin)".
1. If the directory configured to store PowerShell Transcription logs does not exist:
mkdir C:\\ProgramData\\PS_Transcript
2. Assign appropriate permissions to Administrators group and System account:
icacls "C:\\ProgramData\\PS_Transcript" /inheritance:r /grant:r "Administrators:(OI)(CI)(F)" /grant:r "SYSTEM":(OI)(CI)(F)
3. Assign appropriate permissions to user groups:
icacls "C:\\ProgramData\\PS_Transcript" /grant:r "Users":(OI)(CI)(WD,AD) /t /c
icacls "C:\\ProgramData\\PS_Transcript" /grant:r "Authenticated Users":(OI)(CI)(WD,AD) /t /c'
  impact 0.5
  tag check_id: 'C-56868r1259990_chk'
  tag severity: 'medium'
  tag gid: 'V-253415'
  tag rid: 'SV-253415r1259992_rule'
  tag stig_id: 'WN11-CC-000327'
  tag gtitle: 'SRG-OS-000041-GPOS-00019'
  tag fix_id: 'F-56818r1259991_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']

  transcription = registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription')
  output_directory = transcription.OutputDirectory.to_s.strip

  describe transcription do
    it { should have_property 'EnableTranscripting' }
    its('EnableTranscripting') { should cmp 1 }
  end

  # Without an OutputDirectory, transcripts are written to each user's own Documents folder
  describe 'PowerShell Transcription output directory (OutputDirectory)' do
    subject { output_directory }
    it { should_not be_empty }
  end

  unless output_directory.empty?
    ps_directory = output_directory.gsub("'", "''")
    privileged_sids = input('transcript_privileged_sids').map { |sid| "'#{sid}'" }.join(', ')

    # Nonprivileged accounts may only hold write-only rights:
    # WriteData/CreateFiles (2), AppendData/CreateDirectories (4) and Synchronize (1048576)
    violations = json(command: <<~PS).params
      $privileged = @(#{privileged_sids})
      $writeOnly = [int64](2 -bor 4 -bor 1048576)
      $paths = @('#{ps_directory}') + @(Get-ChildItem -LiteralPath '#{ps_directory}' -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
      $violations = foreach ($path in $paths) {
        $acl = Get-Acl -LiteralPath $path -ErrorAction SilentlyContinue
        if (-not $acl) {
          [pscustomobject]@{ Path = $path; Identity = 'N/A'; Rights = 'Unable to read ACL (access denied or path missing; the scan must run as an administrator)' }
          continue
        }
        foreach ($ace in $acl.Access) {
          if ("$($ace.AccessControlType)" -ne 'Allow') { continue }
          try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = $ace.IdentityReference.Value }
          if ($privileged -contains $sid) { continue }
          if (([int64]$ace.FileSystemRights -band (-bnot $writeOnly)) -ne 0) {
            [pscustomobject]@{ Path = $path; Identity = $ace.IdentityReference.Value; Rights = "$($ace.FileSystemRights)" }
          }
        }
      }
      ConvertTo-Json -InputObject @($violations)
    PS

    describe "Nonprivileged read or modify access to the transcript output directory #{output_directory}" do
      subject { violations.map { |v| "#{v['Identity']}: #{v['Rights']} (#{v['Path']})" } }
      it { should be_empty }
    end
  end
end
