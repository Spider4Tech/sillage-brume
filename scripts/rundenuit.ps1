# Campagne de nuit SILLAGE sous Windows, dans WSL 2 (le code C et les outils de la campagne visent Linux).
#
#   .\scripts\rundenuit.cmd [heures]         lance (défaut : 8 h) ; une campagne inachevée est reprise, avec son temps restant
#   .\scripts\rundenuit.cmd 10 -Neuf         repart de zéro (la campagne précédente est archivée)
#   .\scripts\rundenuit.cmd -Statut          où on en est (depuis une autre fenêtre)
#   .\scripts\rundenuit.cmd -Arreter         arrêt propre, reprise possible
#
# Garder la fenêtre ouverte : la fermer arrête la campagne. Ctrl-C arrête proprement et écrit l'archive.
# Windows ne se met pas en veille tant que la fenêtre est ouverte. Guide : docs/CAMPAIGN_24H.md
[CmdletBinding()]
param(
    [Parameter(Position = 0)][double]$Heures = 8,
    [switch]$Neuf,
    [switch]$Statut,
    [switch]$Arreter,
    [string]$Distribution = ""
)
$ErrorActionPreference = "Stop"
if ($Heures -le 0) { Write-Error "Durée invalide : $Heures" }

# wsl.exe écrit ses propres messages en UTF-16 ; WSL_UTF8 les rend lisibles
$env:WSL_UTF8 = "1"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    Write-Host "WSL n'est pas installé. Dans un PowerShell administrateur : wsl --install -d Ubuntu, puis redémarrer."
    exit 1
}

# Choix de la distribution : celle demandée, sinon celle par défaut ; elle doit être en WSL 2
# (stderr redirigé + Stop arrêterait le script sous PowerShell 5.1 au moindre message de wsl.exe)
$ErrorActionPreference = "Continue"
$lignes = & wsl.exe --list --verbose 2>$null | ForEach-Object { ($_ -replace "`0", "").Trim() } | Select-Object -Skip 1 | Where-Object { $_ }
$ErrorActionPreference = "Stop"
$distros = foreach ($l in $lignes) {
    $defaut = $l.StartsWith("*")
    $c = ($l -replace "^\*\s*", "") -split "\s+"
    if ($c.Count -ge 3) { [pscustomobject]@{ Nom = ($c[0..($c.Count - 3)] -join " "); Version = $c[-1]; Defaut = $defaut } }
}
$distros = @($distros | Where-Object { $_.Nom -notmatch "^docker-desktop" })
if ($distros.Count -eq 0) {
    Write-Host "Aucune distribution Linux dans WSL. Lancer : wsl --install -d Ubuntu, puis ouvrir Ubuntu une fois pour créer l'utilisateur."
    exit 1
}
if ($Distribution) { $d = $distros | Where-Object { $_.Nom -eq $Distribution } | Select-Object -First 1 }
else { $d = $distros | Where-Object { $_.Defaut } | Select-Object -First 1; if (-not $d) { $d = $distros[0] } }
if (-not $d) { Write-Host "Distribution introuvable : $Distribution. Disponibles : $($distros.Nom -join ', ')"; exit 1 }
if ($d.Version -ne "2") {
    Write-Host "$($d.Nom) tourne en WSL $($d.Version). Il faut WSL 2 : wsl --set-version $($d.Nom) 2"
    exit 1
}

# Le dossier du script est traduit en chemin Linux par WSL (suffixe /p) : aucun problème d'espaces ni de guillemets
$racine = Split-Path -Parent $PSScriptRoot             # le script vit dans scripts\
$env:SILLAGE_WIN_DIR = $racine
$env:WSLENV = "SILLAGE_WIN_DIR/p"
# Appels directs, pas dans une fonction : wsl.exe garde ainsi la console (mot de passe de sudo, Ctrl-C)
$linux = @("-d", $d.Nom, "--cd", $racine, "--", "bash", "scripts/rundenuit_wsl.sh")

if ($Statut)  { & wsl.exe @linux statut;  exit $LASTEXITCODE }
if ($Arreter) { & wsl.exe @linux arreter; exit $LASTEXITCODE }

# Empêche la veille tant que ce processus vit (annulé par Windows à sa fermeture, même brutale)
Add-Type -Namespace Sillage -Name Veille -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint esFlags);
'@
$ES_CONTINUOUS = [uint32]2147483648                  # 0x80000000
$ES_CONTINUOUS_SYSTEME = [uint32]2147483649          # 0x80000001 : ES_CONTINUOUS + ES_SYSTEM_REQUIRED
[void][Sillage.Veille]::SetThreadExecutionState($ES_CONTINUOUS_SYSTEME)

$b = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
if ($b -and $b.BatteryStatus -eq 1) { Write-Warning "Sur batterie : brancher le secteur." }
if ($b) { Write-Warning "Portable : fermer le capot peut mettre la machine en veille malgré ce blocage ; le laisser ouvert." }
Write-Host "Distribution : $($d.Nom). Calcul dans le clone ~/sillage-brume de WSL. Garder cette fenêtre ouverte."
Write-Host "Pas d'arrêt de sécurité sur la température sous WSL : surveiller le refroidissement."
Write-Host "Windows Update peut redémarrer la machine : suspendre les mises à jour pour la durée de la campagne."
Write-Host ""

try {
    # Point décimal quelle que soit la langue de Windows (10.5, pas 10,5)
    $h = $Heures.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    $n = if ($Neuf) { "1" } else { "0" }
    & wsl.exe @linux lancer $h $n
    $rc = $LASTEXITCODE
}
finally {
    [void][Sillage.Veille]::SetThreadExecutionState($ES_CONTINUOUS)
}
exit $rc
