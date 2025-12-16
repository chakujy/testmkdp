$enrolScriptUrl = "https://intunemakdap.blob.core.windows.net/autopilot/enrol.ps1"
$groupTags = @("None", "WIN-32BIT-APPS", "WIN-64BIT-APPS")
$defaultGroupTag = "WIN-32BIT-APPS"

$exitCode = 0

$logFolder = "$env:ProgramData\makdap\autopilot"

$env:Path += ";C:\Program Files\WindowsPowerShell\Scripts"

$preBoot = -not $env:LocalAppData

if ($preBoot) {
    $env:LocalAppData = "C:\Windows\system32\config\systemprofile\AppData\Local"
    Write-Warning "Set LOCALAPPDATA path explicitly"
}

if ((Get-ExecutionPolicy -Scope Process) -ne "Bypass")
{
    $prePolicy = (Get-ExecutionPolicy -Scope Process)

    Set-ExecutionPolicy Bypass -Scope Process

    Write-Host "Execution policy changed from `"$prePolicy`" to `"Bypass`""
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

try 
{
    if ([Environment]::UserInteractive -and -not(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
	    Write-Warning "Unable to continue, you must be an administrator of the machine to run autopilot enrolment"
        Read-Host
	    return
    }

    while(-not(Test-Connection 8.8.8.8 -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
    	Write-Warning "No internet connection, retrying in 5 seconds ... "
        Start-Sleep -Seconds 5
    }

    If (-not(Test-Path $logFolder)) { New-Item -Path $logFolder -Type Directory -Force | Out-Null }

    Install-PackageProvider -Name NuGet -Force | Out-Null
    Write-Host "Installed latest version of NuGet package provider"

    Install-Module PowerShellGet -Force -AllowClobber | Out-Null
    Write-Host "Installed latest PowerShellGet module"

    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

    $choice = Start-Process -FilePath choice -ArgumentList "/C YN /M `"Register this device in intune? `" /T 10 /D Y" -Wait -PassThru -NoNewWindow
    
    $registerDevice = $choice.ExitCode -eq 1

    if ($registerDevice) 
    {
        $script = Invoke-WebRequest $enrolScriptUrl -UseBasicParsing

        $scriptBlock = [Scriptblock]::Create($script.Content)

        Write-Host "Downloaded enrolment script"

        Write-Host
        Write-Host "Select intune device group tag:"
        Write-Host

        $choiceList = ""
        $defaultChoice = 1

        for($i = 0; $i -lt $groupTags.Length; $i++) {
            if ($groupTags[$i] -eq $defaultGroupTag) {
                Write-Host "$($i + 1): $($groupTags[$i]) (default)"
                $defaultChoice = $i + 1
            }
            else {
                Write-Host "$($i + 1): $($groupTags[$i])"
            }

            $choiceList += "$($i + 1)"
        }

        $choice = Start-Process -FilePath choice -ArgumentList "/C $choiceList /T 10 /D $defaultChoice" -Wait -PassThru -NoNewWindow

        $groupTag = $groupTags[$choice.ExitCode - 1]

        $user = ""

        $choice = Start-Process -FilePath choice -ArgumentList "/C YN /M `"Assign a user to this device? `" /T 10 /D N" -Wait -PassThru -NoNewWindow

        if ($choice.ExitCode -eq 1) 
        {
	        Write-Host
            Write-Host "Enter email address in the format xxxx@makdap.com.au and press enter ... "
            while (-not($user.EndsWith("@makdap.com.au"))) {
                $user = Read-Host
                if ($user -eq "") {
                    break
                }
            }
        }

        Invoke-Command -ScriptBlock $scriptBlock -ArgumentList ($args + @($groupTag, $user))

        Write-Host "Intune device registration completed"

        $exitCode = 1
    }

    $stopwatch =  [system.diagnostics.stopwatch]::StartNew()

    $userName = Get-Process -IncludeUserName -Name explorer -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UserName

    if ($userName)
    {
        $choice = Start-Process -FilePath choice -ArgumentList "/C YN /M `"Force a full Windows Updates refresh (excluding drivers)? `" /T 10 /D Y" -Wait -PassThru -NoNewWindow

        if ($choice.ExitCode -eq 1)
        {
            Write-Host "Running as $userName"

            Install-Module -Name PSWindowsUpdate -Force -AllowClobber

            Write-Host "Installed PSWindowsUpdate"

            try
            {
                Write-Host "Installing windows updates ... "
                Install-WindowsUpdate -AcceptAll -IgnoreReboot -Verbose -NotCategory "Drivers" -MicrosoftUpdate | Out-File "$logFolder\windows_updates_pre_esp.log" -Append
                $exitCode = 1
            }
            catch {
                Write-Warning "Failed to process windows updates"
                Write-Warning $_
                Write-Warning $_.ScriptStackTrace  
            }
            finally {
                $stopwatch.Stop()
                Write-Host "Windows update processing took $([Math]::Floor($stopwatch.Elapsed.TotalMinutes)) minutes"
            }
        }
    }
    else 
    {
        Write-Warning "Running non-interactively, can not process windows updates now ..."
    }

    if ($registerDevice -and $stopwatch.Elapsed.TotalMinutes -lt 10) 
    {
        $delay = 10 - [Math]::Floor($stopwatch.Elapsed.TotalMinutes)
        Write-Host "Waiting $($delay) minutes to allow for intune profile and dynamic group assignment ..."
        Start-Process -FilePath timeout -ArgumentList "/t $($delay * 60)" -NoNewWindow -Wait
    }
}
catch 
{
    Write-Warning "Autopilot script has encounted a fatal error, press enter to continue ..."
    Write-Warning $_
    Write-Warning $_.ScriptStackTrace
    Read-Host
}
finally
{
    if ($PSCommandPath -match "C:") {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -Value $($((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations) + "\??\$PSCommandPath`0`0") -Type MultiString -Force | Out-Null
        Write-Host "$PSCommandPath will be deleted on next reboot"
    }

    Start-Sleep -Seconds 5

    Exit $exitCode

}
