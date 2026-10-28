# VDI workstation detection helper.
#
# InSpec automatically loads all files in libraries/ before evaluating controls,
# making this method available in every control in the profile without any
# explicit require or include.
#
# Detection logic (either condition is sufficient):
#   1. The is_vdi input is set to 'true'  (explicit operator override)
#   2. Any service named in the vdi_services input is currently running
#
# Usage in a control:
#
#   if vdi_workstation?
#     impact 0.0
#     describe 'VDI system detected - this control is not applicable' do
#       skip 'System identified as a VDI workstation via is_vdi flag or a running VDI agent service.'
#     end
#   else
#     # actual check logic
#   end
module VDIHelper
  def vdi_workstation?
    return true if input('is_vdi') == 'true'

    input('vdi_services').any? do |svc|
      powershell(
        "(Get-Service -Name '#{svc}' -ErrorAction SilentlyContinue).Status"
      ).stdout.strip == 'Running'
    end
  rescue StandardError
    nil
  end
end

::Inspec::Rule.include(VDIHelper)