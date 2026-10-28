# Per-user (HKEY_CURRENT_USER) registry helper.
#
# InSpec automatically loads all files in libraries/ before evaluating controls,
# making this method available in every control in the profile without any
# explicit require or include.
#
# STIG checks against HKEY_CURRENT_USER must be performed for each interactive
# user profile, not just the account running the scan. This helper:
#   1. Enumerates profiles via Win32_UserProfile, skipping Special (service)
#      profiles and anything that is not a user SID (S-1-5-21-*)
#   2. Skips profiles that belong to disabled local accounts
#   3. Reads the value from HKEY_USERS\<SID> when the hive is already loaded,
#      otherwise temporarily loads the profile's NTUSER.DAT with "reg load",
#      reads the value, and unloads it again
#
# Returns an Array of Hashes: [{ 'SID' => ..., 'Path' => ..., 'Value' => ..., 'Error' => ... }]
# 'Value' is nil when the value does not exist; 'Error' is set when the hive
# could not be read.
#
# Usage in a control:
#
#   user_registry_values('SOFTWARE\Policies\Microsoft\Windows\CloudContent', 'DisableThirdPartySuggestions').each do |profile|
#     describe "DisableThirdPartySuggestions for #{profile['SID']}" do
#       subject { profile['Value'] }
#       it { should cmp 1 }
#     end
#   end
module UserRegistryHelper
  def user_registry_values(subkey, value_name)
    script = <<~PS
      $disabled = @(Get-LocalUser | Where-Object { -not $_.Enabled } | ForEach-Object { $_.SID.Value })
      $profiles = Get-CimInstance -ClassName Win32_UserProfile |
        Where-Object { -not $_.Special -and $_.SID -like 'S-1-5-21-*' -and $disabled -notcontains $_.SID }
      $results = foreach ($p in $profiles) {
        $mount = $null
        $root = "Registry::HKEY_USERS\\$($p.SID)"
        if (-not $p.Loaded) {
          $hive = Join-Path $p.LocalPath 'NTUSER.DAT'
          if (-not (Test-Path -LiteralPath $hive)) {
            [pscustomobject]@{ SID = $p.SID; Path = $p.LocalPath; Value = $null; Error = 'NTUSER.DAT not found' }
            continue
          }
          $mount = "InSpec_$($p.SID)"
          & reg.exe load "HKU\\$mount" "$hive" 2>&1 | Out-Null
          if ($LASTEXITCODE -ne 0) {
            [pscustomobject]@{ SID = $p.SID; Path = $p.LocalPath; Value = $null; Error = 'Unable to load NTUSER.DAT' }
            continue
          }
          $root = "Registry::HKEY_USERS\\$mount"
        }
        $item = Get-ItemProperty -LiteralPath "$root\\#{subkey}" -Name '#{value_name}' -ErrorAction SilentlyContinue
        [pscustomobject]@{ SID = $p.SID; Path = $p.LocalPath; Value = $item.'#{value_name}'; Error = $null }
        if ($mount) {
          $item = $null
          [gc]::Collect()
          & reg.exe unload "HKU\\$mount" 2>&1 | Out-Null
        }
      }
      ConvertTo-Json -InputObject @($results) -Compress
    PS

    output = powershell(script).stdout.strip
    output.empty? ? [] : Array(JSON.parse(output))
  end
end

::Inspec::Rule.include(UserRegistryHelper)
