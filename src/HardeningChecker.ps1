param(
    [string]$RulesPath = (Join-Path (Join-Path $PSScriptRoot '..') 'rules'),
    [string[]]$ComponentProfile = @('Auto'),
    [ValidateSet('Table','Json','Csv','Html')][string[]]$Output = @('Table'),
    [string]$OutDir = (Join-Path (Join-Path $PSScriptRoot '..') 'out'),
    [string[]]$IncludeTags,
    [string[]]$ExcludeTags,

    [Switch]$ListRules,
    [string]$ListRulesCsv
)

Import-Module (Join-Path $PSScriptRoot 'RuleEngine.psm1') -Force

Write-Host "[Info] Loading component profile..." -ForegroundColor Cyan

$profile = Get-CAHCComponentProfile -ComponentProfile $ComponentProfile
Write-Host "[Info] Component profile: $($profile -join ', ')" -ForegroundColor Cyan

Write-Host "[Info] Loading rules recursively from: $RulesPath" -ForegroundColor Cyan

$rules = Get-CAHCRules `
    -Path $RulesPath `
    -Profile $profile `
    -IncludeTags $IncludeTags `
    -ExcludeTags $ExcludeTags

Write-Host "[Info] Loaded $($rules.Count) rules (including non-applicable ones)." -ForegroundColor Cyan

if ($ListRules) {
    Write-Host ""
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host "                   LISTING LOADED RULES              " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan

    $rules |
        Select-Object id, title, description, type, appliesTo, severity, tags |
        Format-Table -AutoSize

    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host ""
}

if ($ListRulesCsv) {
    try {
        $csvPath = $ListRulesCsv

        $rules |
            Select-Object id, title, description, type, appliesTo, severity, tags |
            Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath

        Write-Host "[Info] Rules exported in : $csvPath" -ForegroundColor Green
    }
    catch {
        Write-Warning "[Error] Impossible to export rules list : $_"
    }
}

if ($ListRules -or $ListRulesCsv) {
    Write-Host "[Info] Listing rules ended" -ForegroundColor Cyan
    return
}

Write-Host "[Info] Running hardening checks..." -ForegroundColor Cyan

$results = Invoke-CAHCRules -Rules $rules

Write-Host "[Info] Computing compliance score..." -ForegroundColor Cyan

$score = Get-CAHCScore -Results $results

Write-Host "[Info] Exporting results..." -ForegroundColor Cyan

Export-CAHCResults `
    -Results $results `
    -Score $score `
    -Formats $Output `
    -OutDir $OutDir `
    -Profile $profile

Write-Host ""
Write-Host "[Done] Compliance score: $score%" -ForegroundColor Green
Write-Host "Results exported to: $OutDir" -ForegroundColor Green