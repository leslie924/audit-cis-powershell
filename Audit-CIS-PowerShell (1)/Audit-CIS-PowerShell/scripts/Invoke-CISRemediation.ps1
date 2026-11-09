<#
.SYNOPSIS
    Applique à distance (WinRM) une sélection de mesures de durcissement CIS jugées sans risque pour le lab.

.DESCRIPTION
    Corrige les non-conformités les plus courantes relevées par Invoke-CISAudit.ps1 :
    stratégie de mots de passe et de verrouillage, compte Invité, SMBv1, signature SMB,
    LLMNR, NTLMv2, pare-feu, UAC, AutoRun, journalisation PowerShell, taille du journal
    Sécurité, stratégie d'audit et désactivation de PowerShell 2.0.

    Mesures volontairement NON appliquées (risque de couper l'accès au lab) :
    désactivation du compte Administrateur intégré, modification de WinRM, du RDP
    ou de BitLocker. Elles restent signalées par l'audit.

    Utiliser -Simulation pour afficher les actions sans rien modifier.

.EXAMPLE
    .\Invoke-CISRemediation.ps1 -Simulation
    .\Invoke-CISRemediation.ps1 -Computers PC02
    .\Invoke-CISRemediation.ps1

.NOTES
    Projet personnel – Leslie Kamguem. À n'utiliser que sur un environnement de test.
#>
[CmdletBinding()]
param(
    [string]$ComputersFile = ".\computers.txt",
    [string[]]$Computers,
    [switch]$Simulation,
    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $ComputersFile)) { throw "Fichier introuvable : $ComputersFile" }
if (-not $Credential) { $Credential = Get-Credential -Message "Identifiants administrateur pour la remédiation" }

$remediationBlock = {
    param([bool]$DryRun)
    $out = New-Object System.Collections.Generic.List[object]

    function Invoke-Fix {
        param([string]$Id, [string]$Label, [scriptblock]$Action)
        if ($DryRun) { $out.Add([pscustomobject]@{ Id = $Id; Mesure = $Label; Resultat = 'SIMULATION' }); return }
        try { & $Action | Out-Null; $out.Add([pscustomobject]@{ Id = $Id; Mesure = $Label; Resultat = 'APPLIQUÉ' }) }
        catch { $out.Add([pscustomobject]@{ Id = $Id; Mesure = $Label; Resultat = "ÉCHEC : $($_.Exception.Message)" }) }
    }
    function Set-Reg {
        param($Path, $Name, $Value)
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord
    }

    # Stratégie de mots de passe (s'applique aux prochains changements de mot de passe)
    Invoke-Fix '1.1/1.3/1.4' 'Mots de passe : longueur 14, durée max 365 j, historique 24' {
        net accounts /minpwlen:14 /maxpwage:365 /uniquepw:24 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "net accounts a échoué ($LASTEXITCODE)" }
    }
    Invoke-Fix '1.2' 'Mots de passe : complexité exigée' {
        $cfg = Join-Path $env:TEMP 'cis_fix.cfg'; $db = Join-Path $env:TEMP 'cis_fix.sdb'
        secedit /export /cfg $cfg /quiet | Out-Null
        (Get-Content $cfg) -replace '^PasswordComplexity\s*=.*', 'PasswordComplexity = 1' | Set-Content $cfg -Encoding Unicode
        secedit /configure /db $db /cfg $cfg /areas SECURITYPOLICY /quiet | Out-Null
        Remove-Item $cfg, $db -Force -ErrorAction SilentlyContinue
    }
    Invoke-Fix '1.5/1.6' 'Verrouillage : 5 tentatives, 15 minutes' {
        net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "net accounts a échoué ($LASTEXITCODE)" }
    }
    Invoke-Fix '2.1' 'Compte Invité désactivé' {
        Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Disable-LocalUser
    }
    Invoke-Fix '3.1' 'SMBv1 désactivé' { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false }
    Invoke-Fix '3.2' 'Signature SMB exigée' { Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -Confirm:$false }
    Invoke-Fix '3.3' 'LLMNR désactivé' { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 }
    Invoke-Fix '3.4' 'NTLMv2 uniquement' { Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 5 }
    Invoke-Fix '4.x' 'Pare-feu actif sur les 3 profils, entrant bloqué par défaut' {
        Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block
    }
    Invoke-Fix '6.1/6.2' 'UAC activé avec consentement sur le bureau sécurisé' {
        $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Set-Reg $p 'EnableLUA' 1
        Set-Reg $p 'ConsentPromptBehaviorAdmin' 2
    }
    Invoke-Fix '6.3' 'AutoRun désactivé sur tous les lecteurs' {
        Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255
    }
    Invoke-Fix '6.5' 'Service Registre à distance désactivé' {
        Stop-Service RemoteRegistry -Force -ErrorAction SilentlyContinue
        Set-Service RemoteRegistry -StartupType Disabled
    }
    Invoke-Fix '6.7' 'PowerShell 2.0 désactivé (redémarrage éventuel)' {
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
    }
    Invoke-Fix '7.1' 'Journalisation des blocs de script PowerShell' {
        Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1
    }
    Invoke-Fix '7.2' 'Journal Sécurité porté à 192 Mo' {
        wevtutil sl Security /ms:201326592
        if ($LASTEXITCODE -ne 0) { throw "wevtutil a échoué ($LASTEXITCODE)" }
    }
    Invoke-Fix '7.3/7.4/7.5' "Stratégie d'audit : ouvertures de session, comptes, processus" {
        auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"{0CCE9235-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null
    }
    $out
}

$list = Get-Content $ComputersFile | Where-Object { $_.Trim() -and -not $_.StartsWith('#') }
foreach ($line in $list) {
    $name, $ip = $line.Trim() -split ';'
    if ($Computers -and $name -notin $Computers) { continue }
    $mode = if ($Simulation) { ' (simulation)' } else { '' }
    Write-Host "`n=== Remédiation de $name ($ip)$mode ===" -ForegroundColor Cyan
    try {
        Invoke-Command -ComputerName $ip -Credential $Credential -ScriptBlock $remediationBlock -ArgumentList ([bool]$Simulation) -ErrorAction Stop |
            Format-Table Id, Mesure, Resultat -AutoSize | Out-Host
    } catch {
        Write-Host "$name inaccessible : $($_.Exception.Message)" -ForegroundColor Red
    }
}
Write-Host "`nRelancez .\Invoke-CISAudit.ps1 pour mesurer le gain de conformité."
