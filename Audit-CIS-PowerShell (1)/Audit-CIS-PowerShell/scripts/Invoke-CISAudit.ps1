<#
.SYNOPSIS
    Audit de durcissement Windows inspiré du CIS Benchmark, exécuté à distance par WinRM.

.DESCRIPTION
    Lit la liste des postes dans computers.txt (format Nom;IP), vérifie 34 points de
    configuration de sécurité sur chaque poste accessible (mots de passe, comptes,
    protocoles réseau, pare-feu, antivirus, système, journalisation) et produit :
      - un score de conformité par poste ;
      - un rapport CSV détaillé ;
      - un rapport HTML (synthèse, non-conformités les plus fréquentes, détail par poste) ;
      - une trace dans CIS-Audit.log.
    Le script est en LECTURE SEULE : il ne modifie rien sur les postes.

.EXAMPLE
    .\Invoke-CISAudit.ps1
    .\Invoke-CISAudit.ps1 -ComputersFile .\computers.txt -OutputDir .\Rapports

.NOTES
    Projet personnel – Leslie Kamguem – inspiré du CIS Microsoft Windows 10 Benchmark (niveau 1).
    Les contrôles sont une sélection pédagogique, pas une implémentation complète du benchmark.
#>
[CmdletBinding()]
param(
    [string]$ComputersFile = ".\computers.txt",
    [string]$OutputDir     = ".\Rapports",
    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'
$auditDate = Get-Date
$stamp     = $auditDate.ToString('yyyyMMdd-HHmm')
$logFile   = Join-Path $OutputDir 'CIS-Audit.log'

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }

function Write-Log {
    param([string]$Message)
    "$(Get-Date -Format 'dd/MM/yyyy HH:mm:ss') ; $Message" | Out-File -FilePath $logFile -Append -Encoding UTF8
}

if (-not (Test-Path $ComputersFile)) { throw "Fichier introuvable : $ComputersFile" }
if (-not $Credential) { $Credential = Get-Credential -Message "Identifiants administrateur pour l'audit des postes" }

# ---------------------------------------------------------------------------
# Bloc exécuté sur chaque poste (lecture seule)
# ---------------------------------------------------------------------------
$auditBlock = {
    $results = New-Object System.Collections.Generic.List[object]

    function Add-Check {
        param($Id, $Cat, $Title, $Expected, $Actual, $Ok, $Sev, $Fix)
        if ($null -eq $Ok)  { $status = 'NON EVALUE' }
        elseif ($Ok)        { $status = 'CONFORME' }
        else                { $status = 'NON CONFORME' }
        if ($null -eq $Actual -or "$Actual" -eq '') { $Actual = 'Non défini' }
        $results.Add([pscustomobject]@{
            Id = $Id; Categorie = $Cat; Controle = $Title; Attendu = $Expected
            Actuel = "$Actual"; Statut = $status; Severite = $Sev; Remediation = $Fix
        })
    }
    function Get-Reg {
        param($Path, $Name)
        try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
    }
    function Get-AuditSetting {
        param($Guid)
        try {
            $row = auditpol /get /subcategory:"$Guid" /r | ConvertFrom-Csv | Select-Object -First 1
            $raw = "$(@($row.PSObject.Properties)[4].Value)"
            # Valeur normalisée, indépendante de la langue de Windows et de l'encodage de la console :
            # FR « Succès et échec » / « Réussite » / « Échec » / « Pas d'audit » – EN « Success and Failure » / « Success » / « Failure »
            $s = $raw -match 'Succ|ussite'
            $f = $raw -match 'chec|Fail'
            if ($s -and $f) { 'Succès et échec' } elseif ($s) { 'Succès' } elseif ($f) { 'Échec' } else { 'Aucun audit' }
        } catch { $null }
    }

    # --- Stratégie de mots de passe et de verrouillage (export secedit) ---
    $sec = @{}
    $cfg = Join-Path $env:TEMP 'cis_secpol.cfg'
    try {
        secedit /export /cfg $cfg /quiet | Out-Null
        Get-Content $cfg | ForEach-Object {
            if ($_ -match '^\s*(\w+)\s*=\s*(.*)$') { $sec[$Matches[1]] = $Matches[2].Trim() }
        }
    } catch {} finally { Remove-Item $cfg -Force -ErrorAction SilentlyContinue }
    function SecInt { param($n) if ($sec.ContainsKey($n)) { [int]$sec[$n] } else { $null } }

    $v = SecInt 'MinimumPasswordLength'
    Add-Check '1.1' 'Mots de passe' 'Longueur minimale du mot de passe' '>= 14 caractères' $v ($v -ge 14) 'Élevée' 'net accounts /minpwlen:14'
    $v = SecInt 'PasswordComplexity'
    Add-Check '1.2' 'Mots de passe' 'Complexité du mot de passe exigée' '1 (activée)' $v ($v -eq 1) 'Élevée' 'secpol.msc > Stratégies de comptes > Le mot de passe doit respecter des exigences de complexité'
    $v = SecInt 'MaximumPasswordAge'
    Add-Check '1.3' 'Mots de passe' 'Durée de vie maximale du mot de passe' '1 à 365 jours' $v (($v -gt 0) -and ($v -le 365)) 'Moyenne' 'net accounts /maxpwage:365'
    $v = SecInt 'PasswordHistorySize'
    Add-Check '1.4' 'Mots de passe' 'Historique des mots de passe' '>= 24' $v ($v -ge 24) 'Moyenne' 'net accounts /uniquepw:24'
    $v = SecInt 'LockoutBadCount'
    Add-Check '1.5' 'Mots de passe' 'Seuil de verrouillage du compte' '1 à 5 tentatives' $v (($v -ge 1) -and ($v -le 5)) 'Élevée' 'net accounts /lockoutthreshold:5'
    $v = SecInt 'LockoutDuration'
    Add-Check '1.6' 'Mots de passe' 'Durée de verrouillage du compte' '>= 15 minutes' $v ($v -ge 15) 'Moyenne' 'net accounts /lockoutduration:15'

    # --- Comptes locaux ---
    try {
        $guest = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }
        Add-Check '2.1' 'Comptes' 'Compte Invité désactivé' 'Désactivé' $(if ($guest.Enabled) {'Activé'} else {'Désactivé'}) (-not $guest.Enabled) 'Élevée' "Get-LocalUser | Where-Object { `$_.SID -like '*-501' } | Disable-LocalUser"
        $adm = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }
        Add-Check '2.2' 'Comptes' 'Compte Administrateur intégré désactivé' 'Désactivé' $(if ($adm.Enabled) {'Activé'} else {'Désactivé'}) (-not $adm.Enabled) 'Moyenne' "Créer un compte d'administration nominatif, puis désactiver le compte intégré (SID -500)"
    } catch {
        Add-Check '2.1' 'Comptes' 'Compte Invité désactivé' 'Désactivé' $_.Exception.Message $null 'Élevée' ''
    }
    try {
        $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544')
        Add-Check '2.3' 'Comptes' "Nombre de membres du groupe Administrateurs" '<= 2' "$($admins.Count) ($(($admins.Name) -join ', '))" ($admins.Count -le 2) 'Moyenne' 'Retirer les comptes inutiles du groupe Administrateurs (moindre privilège)'
    } catch {
        Add-Check '2.3' 'Comptes' "Nombre de membres du groupe Administrateurs" '<= 2' $_.Exception.Message $null 'Moyenne' ''
    }

    # --- Protocoles réseau ---
    try {
        $smb = Get-SmbServerConfiguration
        Add-Check '3.1' 'Réseau' 'SMBv1 désactivé' 'False' $smb.EnableSMB1Protocol (-not $smb.EnableSMB1Protocol) 'Élevée' 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force'
        Add-Check '3.2' 'Réseau' 'Signature SMB exigée (serveur)' 'True' $smb.RequireSecuritySignature ($smb.RequireSecuritySignature) 'Moyenne' 'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force'
    } catch {
        Add-Check '3.1' 'Réseau' 'SMBv1 désactivé' 'False' $_.Exception.Message $null 'Élevée' ''
    }
    $v = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
    Add-Check '3.3' 'Réseau' 'LLMNR désactivé' '0' $v ($v -eq 0) 'Moyenne' "Clé HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient, valeur EnableMulticast = 0"
    $v = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
    Add-Check '3.4' 'Réseau' 'Authentification NTLMv2 uniquement (refus LM/NTLMv1)' '5' $v ($v -eq 5) 'Élevée' "HKLM\SYSTEM\CurrentControlSet\Control\Lsa, LmCompatibilityLevel = 5"
    $deny = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    $nla  = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    $rdpTxt = if ($deny -eq 1) { 'RDP désactivé' } else { "RDP actif, NLA = $nla" }
    Add-Check '3.5' 'Réseau' 'Bureau à distance désactivé ou protégé par NLA' 'RDP désactivé ou NLA = 1' $rdpTxt (($deny -eq 1) -or ($nla -eq 1)) 'Moyenne' 'Désactiver RDP, ou activer « Autoriser uniquement les connexions avec NLA »'
    try {
        $unenc = (Get-Item WSMan:\localhost\Service\AllowUnencrypted).Value
        Add-Check '3.6' 'Réseau' 'WinRM : trafic non chiffré refusé' 'false' $unenc ($unenc -eq 'false') 'Élevée' 'Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false'
        $basic = (Get-Item WSMan:\localhost\Service\Auth\Basic).Value
        Add-Check '3.7' 'Réseau' 'WinRM : authentification Basic désactivée' 'false' $basic ($basic -eq 'false') 'Élevée' 'Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false'
    } catch {
        Add-Check '3.6' 'Réseau' 'WinRM : trafic non chiffré refusé' 'false' $_.Exception.Message $null 'Élevée' ''
    }

    # --- Pare-feu ---
    try {
        $n = 1
        foreach ($p in 'Domain', 'Private', 'Public') {
            $prof = Get-NetFirewallProfile -Name $p
            Add-Check "4.$n" 'Pare-feu' "Pare-feu actif – profil $p" 'True' "$($prof.Enabled)" ("$($prof.Enabled)" -eq 'True') 'Élevée' "Set-NetFirewallProfile -Name $p -Enabled True"
            $n++
        }
        $pub = Get-NetFirewallProfile -Name Public
        Add-Check '4.4' 'Pare-feu' 'Connexions entrantes bloquées par défaut – profil Public' 'Block' "$($pub.DefaultInboundAction)" ("$($pub.DefaultInboundAction)" -in 'Block', 'NotConfigured') 'Moyenne' 'Set-NetFirewallProfile -Name Public -DefaultInboundAction Block'
    } catch {
        Add-Check '4.1' 'Pare-feu' 'Pare-feu actif' 'True' $_.Exception.Message $null 'Élevée' ''
    }

    # --- Antivirus Microsoft Defender ---
    try {
        $mp = Get-MpComputerStatus
        Add-Check '5.1' 'Antivirus' 'Defender : protection en temps réel active' 'True' $mp.RealTimeProtectionEnabled ($mp.RealTimeProtectionEnabled) 'Élevée' 'Set-MpPreference -DisableRealtimeMonitoring $false'
        Add-Check '5.2' 'Antivirus' 'Defender : signatures à jour' '<= 7 jours' "$($mp.AntivirusSignatureAge) jour(s)" ($mp.AntivirusSignatureAge -le 7) 'Élevée' 'Update-MpSignature'
    } catch {
        Add-Check '5.1' 'Antivirus' 'Defender : protection en temps réel active' 'True' 'Defender indisponible (autre antivirus ?)' $null 'Élevée' ''
    }

    # --- Système ---
    $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $v = Get-Reg $sys 'EnableLUA'
    Add-Check '6.1' 'Système' 'Contrôle de compte utilisateur (UAC) activé' '1' $v ($v -eq 1) 'Élevée' "$sys, EnableLUA = 1"
    $v = Get-Reg $sys 'ConsentPromptBehaviorAdmin'
    Add-Check '6.2' 'Système' 'UAC : demande de consentement sur le bureau sécurisé' '2' $v ($v -eq 2) 'Faible' "$sys, ConsentPromptBehaviorAdmin = 2"
    $v = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
    Add-Check '6.3' 'Système' 'Exécution automatique (AutoRun) désactivée' '255' $v ($v -eq 255) 'Moyenne' "HKLM\...\Policies\Explorer, NoDriveTypeAutoRun = 255"
    try {
        $wu = (Get-Service wuauserv).StartType
        Add-Check '6.4' 'Système' 'Service Windows Update non désactivé' 'Différent de Disabled' $wu ("$wu" -ne 'Disabled') 'Élevée' 'Set-Service wuauserv -StartupType Manual'
        $rr = (Get-Service RemoteRegistry).StartType
        Add-Check '6.5' 'Système' 'Service Registre à distance désactivé' 'Disabled' $rr ("$rr" -eq 'Disabled') 'Moyenne' 'Set-Service RemoteRegistry -StartupType Disabled'
    } catch {}
    try {
        $bl = Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='C:'"
        $txt = if ($bl.ProtectionStatus -eq 1) { 'Protégé' } else { 'Non chiffré' }
        Add-Check '6.6' 'Système' 'Disque système chiffré (BitLocker)' 'Protégé' $txt ($bl.ProtectionStatus -eq 1) 'Moyenne' 'Activer BitLocker sur C: (nécessite un TPM virtuel sous VMware)'
    } catch {
        Add-Check '6.6' 'Système' 'Disque système chiffré (BitLocker)' 'Protégé' 'BitLocker indisponible' $null 'Moyenne' ''
    }
    try {
        $ps2 = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).State
        Add-Check '6.7' 'Système' 'PowerShell 2.0 désactivé (contournement de la journalisation)' 'Disabled' $ps2 ("$ps2" -eq 'Disabled') 'Moyenne' 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart'
    } catch {
        Add-Check '6.7' 'Système' 'PowerShell 2.0 désactivé' 'Disabled' $_.Exception.Message $null 'Moyenne' ''
    }

    # --- Journalisation et audit ---
    $v = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    Add-Check '7.1' 'Journalisation' 'Journalisation des blocs de script PowerShell' '1' $v ($v -eq 1) 'Moyenne' 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging, EnableScriptBlockLogging = 1'
    try {
        $size = (Get-WinEvent -ListLog Security).MaximumSizeInBytes
        Add-Check '7.2' 'Journalisation' 'Taille du journal Sécurité' '>= 192 Mo' "$([math]::Round($size / 1MB)) Mo" ($size -ge 196608KB) 'Moyenne' 'wevtutil sl Security /ms:201326592'
    } catch {}
    $v = Get-AuditSetting '{0CCE9215-69AE-11D9-BED3-505054503030}'
    Add-Check '7.3' 'Journalisation' 'Audit des ouvertures de session (succès et échecs)' 'Succès et échec' $v ($v -eq 'Succès et échec') 'Élevée' 'auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable'
    $v = Get-AuditSetting '{0CCE9235-69AE-11D9-BED3-505054503030}'
    Add-Check '7.4' 'Journalisation' 'Audit de la gestion des comptes utilisateur' 'Succès et échec' $v ($v -eq 'Succès et échec') 'Moyenne' 'auditpol /set /subcategory:"{0CCE9235-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable'
    $v = Get-AuditSetting '{0CCE922B-69AE-11D9-BED3-505054503030}'
    Add-Check '7.5' 'Journalisation' 'Audit de la création de processus' 'Succès' $v ($v -in 'Succès', 'Succès et échec') 'Moyenne' 'auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable'

    [pscustomobject]@{
        Hostname = $env:COMPUTERNAME
        OS       = (Get-CimInstance Win32_OperatingSystem).Caption
        Checks   = $results
    }
}

# ---------------------------------------------------------------------------
# Exécution sur le parc
# ---------------------------------------------------------------------------
Write-Log "Début de l'audit CIS"
$allRows  = New-Object System.Collections.Generic.List[object]
$summary  = New-Object System.Collections.Generic.List[object]

$computers = Get-Content $ComputersFile | Where-Object { $_.Trim() -and -not $_.StartsWith('#') }
foreach ($line in $computers) {
    $name, $ip = $line.Trim() -split ';'
    Write-Host "Audit de $name ($ip)..." -ForegroundColor Cyan

    if (-not (Test-Connection -ComputerName $ip -Count 1 -Quiet)) {
        Write-Log "$name ; INACCESSIBLE (ping)"
        $summary.Add([pscustomobject]@{ Poste = $name; IP = $ip; OS = '-'; Etat = 'INACCESSIBLE'; Conformes = 0; NonConformes = 0; NonEvalues = 0; Score = $null; Critiques = 0 })
        continue
    }
    try {
        $r = Invoke-Command -ComputerName $ip -Credential $Credential -ScriptBlock $auditBlock -ErrorAction Stop
    } catch {
        Write-Log "$name ; INACCESSIBLE (WinRM) ; $($_.Exception.Message)"
        $summary.Add([pscustomobject]@{ Poste = $name; IP = $ip; OS = '-'; Etat = 'INACCESSIBLE'; Conformes = 0; NonConformes = 0; NonEvalues = 0; Score = $null; Critiques = 0 })
        continue
    }

    foreach ($c in $r.Checks) {
        $allRows.Add([pscustomobject]@{
            Poste = $name; IP = $ip; Id = $c.Id; Categorie = $c.Categorie; Controle = $c.Controle
            Attendu = $c.Attendu; Actuel = $c.Actuel; Statut = $c.Statut; Severite = $c.Severite
            Remediation = $c.Remediation; DateAudit = $auditDate.ToString('dd/MM/yyyy HH:mm')
        })
    }
    $ok  = @($r.Checks | Where-Object Statut -eq 'CONFORME').Count
    $ko  = @($r.Checks | Where-Object Statut -eq 'NON CONFORME').Count
    $ne  = @($r.Checks | Where-Object Statut -eq 'NON EVALUE').Count
    $crit = @($r.Checks | Where-Object { $_.Statut -eq 'NON CONFORME' -and $_.Severite -eq 'Élevée' }).Count
    $score = if (($ok + $ko) -gt 0) { [math]::Round($ok / ($ok + $ko) * 100, 1) } else { 0 }
    $summary.Add([pscustomobject]@{ Poste = $name; IP = $ip; OS = $r.OS; Etat = 'AUDITÉ'; Conformes = $ok; NonConformes = $ko; NonEvalues = $ne; Score = $score; Critiques = $crit })
    Write-Log "$name ; Score $score % ; $ko non-conformité(s) dont $crit de sévérité élevée"
}

# ---------------------------------------------------------------------------
# Affichage console
# ---------------------------------------------------------------------------
Write-Host "`n--- Synthèse de l'audit CIS ---" -ForegroundColor Yellow
$summary | Format-Table Poste, IP, Etat, Conformes, NonConformes, NonEvalues, @{ n = 'Score (%)'; e = { $_.Score } }, @{ n = 'Critiques'; e = { $_.Critiques } } -AutoSize | Out-Host

$audited = @($summary | Where-Object Etat -eq 'AUDITÉ')
$parkScore = if ($audited.Count) { [math]::Round(($audited | Measure-Object Score -Average).Average, 1) } else { 0 }
Write-Host "Score moyen du parc : $parkScore %" -ForegroundColor Yellow

$top = $allRows | Where-Object Statut -eq 'NON CONFORME' | Group-Object Id |
    Sort-Object Count -Descending | Select-Object -First 10 |
    ForEach-Object { [pscustomobject]@{ Id = $_.Name; Controle = $_.Group[0].Controle; Severite = $_.Group[0].Severite; Postes = $_.Count; Remediation = $_.Group[0].Remediation } }

# ---------------------------------------------------------------------------
# Export CSV
# ---------------------------------------------------------------------------
$csvPath = Join-Path $OutputDir "CIS-Audit-$stamp.csv"
$allRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'

# ---------------------------------------------------------------------------
# Rapport HTML
# ---------------------------------------------------------------------------
function HtmlEnc { param($s) [System.Net.WebUtility]::HtmlEncode("$s") }
function Inv { param($n) ([double]$n).ToString([cultureinfo]::InvariantCulture) }  # largeur CSS avec point décimal
function Get-ScoreColor { param($s) if ($null -eq $s) { '#9e9e9e' } elseif ($s -ge 80) { '#2e7d32' } elseif ($s -ge 50) { '#ef8f00' } else { '#c62828' } }

$sb = New-Object System.Text.StringBuilder
[void]$sb.Append(@"
<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><title>Audit CIS – $(HtmlEnc $auditDate.ToString('dd/MM/yyyy'))</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222;background:#fafafa}
h1{color:#1f3a5f;margin-bottom:4px}h2{color:#1f3a5f;border-bottom:2px solid #1f3a5f;padding-bottom:4px;margin-top:32px}
.sub{color:#666;margin-top:0}
.cards{display:flex;gap:14px;flex-wrap:wrap}
.card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:14px 18px;min-width:190px}
.card b{font-size:26px;display:block}
.bar{background:#eee;border-radius:4px;height:10px;margin-top:8px}.bar i{display:block;height:10px;border-radius:4px}
table{border-collapse:collapse;width:100%;background:#fff;margin:10px 0 20px;font-size:13px}
th{background:#1f3a5f;color:#fff;text-align:left;padding:7px}td{border:1px solid #ddd;padding:6px;vertical-align:top}
tr:nth-child(even) td{background:#f5f7fa}
.ok{color:#2e7d32;font-weight:bold}.ko{color:#c62828;font-weight:bold}.ne{color:#777;font-weight:bold}
.sev-Élevée{color:#c62828}.sev-Moyenne{color:#ef8f00}.sev-Faible{color:#555}
code{font-size:12px;background:#f0f0f0;padding:1px 4px}
.note{color:#666;font-size:12px}
</style></head><body>
<h1>Audit de durcissement Windows (inspiré du CIS Benchmark)</h1>
<p class="sub">Date de l'audit : $(HtmlEnc $auditDate.ToString('dd/MM/yyyy HH:mm')) – $($summary.Count) poste(s) – 34 contrôles par poste</p>
<div class="cards">
<div class="card"><span>Score moyen du parc</span><b style="color:$(Get-ScoreColor $parkScore)">$parkScore %</b><div class="bar"><i style="width:$(Inv $parkScore)%;background:$(Get-ScoreColor $parkScore)"></i></div></div>
<div class="card"><span>Postes audités</span><b>$($audited.Count) / $($summary.Count)</b></div>
<div class="card"><span>Non-conformités</span><b>$(@($allRows | Where-Object Statut -eq 'NON CONFORME').Count)</b></div>
<div class="card"><span>Dont sévérité élevée</span><b style="color:#c62828">$(($summary | Measure-Object Critiques -Sum).Sum)</b></div>
</div>
<h2>Score par poste</h2>
<table><tr><th>Poste</th><th>IP</th><th>Système</th><th>État</th><th>Conformes</th><th>Non conformes</th><th>Non évalués</th><th>Sévérité élevée</th><th style="width:22%">Score</th></tr>
"@)
foreach ($s in $summary) {
    $col = Get-ScoreColor $s.Score
    $scoreCell = if ($null -eq $s.Score) { '-' } else { "<b style='color:$col'>$($s.Score) %</b><div class='bar'><i style='width:$(Inv $s.Score)%;background:$col'></i></div>" }
    [void]$sb.Append("<tr><td>$(HtmlEnc $s.Poste)</td><td>$(HtmlEnc $s.IP)</td><td>$(HtmlEnc $s.OS)</td><td>$(HtmlEnc $s.Etat)</td><td>$($s.Conformes)</td><td>$($s.NonConformes)</td><td>$($s.NonEvalues)</td><td>$($s.Critiques)</td><td>$scoreCell</td></tr>")
}
[void]$sb.Append("</table><h2>Non-conformités les plus fréquentes</h2><table><tr><th>Id</th><th>Contrôle</th><th>Sévérité</th><th>Postes concernés</th><th>Remédiation</th></tr>")
foreach ($t in $top) {
    [void]$sb.Append("<tr><td>$(HtmlEnc $t.Id)</td><td>$(HtmlEnc $t.Controle)</td><td class='sev-$($t.Severite)'>$(HtmlEnc $t.Severite)</td><td>$($t.Postes) / $($audited.Count)</td><td><code>$(HtmlEnc $t.Remediation)</code></td></tr>")
}
[void]$sb.Append("</table><h2>Détail par poste</h2>")
foreach ($name in ($allRows | Select-Object -ExpandProperty Poste -Unique)) {
    [void]$sb.Append("<h3>$(HtmlEnc $name)</h3><table><tr><th>Id</th><th>Catégorie</th><th>Contrôle</th><th>Attendu</th><th>Valeur actuelle</th><th>Statut</th><th>Sévérité</th></tr>")
    foreach ($row in ($allRows | Where-Object Poste -eq $name)) {
        $cls = switch ($row.Statut) { 'CONFORME' { 'ok' } 'NON CONFORME' { 'ko' } default { 'ne' } }
        [void]$sb.Append("<tr><td>$(HtmlEnc $row.Id)</td><td>$(HtmlEnc $row.Categorie)</td><td>$(HtmlEnc $row.Controle)</td><td>$(HtmlEnc $row.Attendu)</td><td>$(HtmlEnc $row.Actuel)</td><td class='$cls'>$(HtmlEnc $row.Statut)</td><td class='sev-$($row.Severite)'>$(HtmlEnc $row.Severite)</td></tr>")
    }
    [void]$sb.Append('</table>')
}
[void]$sb.Append("<p class='note'>Score = contrôles conformes / contrôles évalués. Sélection de contrôles inspirée du CIS Microsoft Windows 10 Benchmark (niveau 1), à visée pédagogique. Audit en lecture seule.</p></body></html>")

$htmlPath = Join-Path $OutputDir "CIS-Audit-$stamp.html"
$sb.ToString() | Out-File -FilePath $htmlPath -Encoding UTF8

Write-Log "Rapports générés : $csvPath ; $htmlPath"
Write-Log "Fin de l'audit CIS (score moyen du parc : $parkScore %)"
Write-Host "`nRapport CSV  : $csvPath"
Write-Host "Rapport HTML : $htmlPath"
Write-Host "Journal      : $logFile"
