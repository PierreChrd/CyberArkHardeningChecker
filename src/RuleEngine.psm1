# RuleEngine.psm1

function Get-CAHCComponentProfile {
    [CmdletBinding()]
    param(
        [string[]]$ComponentProfile = @('Auto')
    )
    $set = New-Object System.Collections.Generic.HashSet[string]
    if ($ComponentProfile -contains 'Auto') {
        $set.Add('Windows') | Out-Null
        try { if (Get-Service -Name 'CyberArk Privileged Session Manager' -ErrorAction SilentlyContinue) { $set.Add('PSM') | Out-Null } } catch {}
        try { if (Get-Service -Name 'CyberArk Central Policy Manager' -ErrorAction SilentlyContinue) { $set.Add('CPM') | Out-Null } } catch {}
        try { if (Get-Service -Name 'PrivateArk Server' -ErrorAction SilentlyContinue) { $set.Add('Vault') | Out-Null } } catch {}
        try {
            if (Get-Module -ListAvailable -Name WebAdministration) {
                Import-Module WebAdministration -ErrorAction SilentlyContinue
                if (Get-ChildItem IIS:\AppPools | Where-Object { $_.Name -eq 'PVWAAppPool' }) { $set.Add('PVWA') | Out-Null }
                elseif (Get-ChildItem IIS:\Sites | Where-Object { $_.Name -match 'PasswordVault' }) { $set.Add('PVWA') | Out-Null }
            }
        } catch {}
    } else {
        foreach ($c in $ComponentProfile) { $set.Add($c) | Out-Null }
        if (-not ($set.Contains('Windows'))) { $set.Add('Windows') | Out-Null }
    }
    return [string[]]$set
}

function Get-CAHCRules {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$Profile,
        [string[]]$IncludeTags,
        [string[]]$ExcludeTags
    )
    $files = Get-ChildItem -Path $Path -Filter *.json -File -Recurse
    $rules = @()
    foreach ($f in $files) {
        try { $r = Get-Content $f.FullName -Raw | ConvertFrom-Json } catch { Write-Warning "Invalid JSON: $($f.FullName)"; continue }
        if (-not $r.appliesTo) { $r | Add-Member -NotePropertyName appliesTo -NotePropertyValue @('Windows') }
        if (-not $r.severity) { $r | Add-Member -NotePropertyName severity -NotePropertyValue 'medium' }
        if ($IncludeTags) {
            if (-not ($r.tags) -or -not (@($r.tags) | Where-Object { $IncludeTags -contains $_ })) { continue }
        }
        if ($ExcludeTags) {
            if ($r.tags -and (@($r.tags) | Where-Object { $ExcludeTags -contains $_ }).Count -gt 0) { continue }
        }
        if ($Profile) {
            if (-not (@($r.appliesTo) | Where-Object { $Profile -contains $_ })) { $r | Add-Member -NotePropertyName Applicable -NotePropertyValue $false -Force; $rules += $r; continue }
        }
        $r | Add-Member -NotePropertyName Applicable -NotePropertyValue $true -Force
        $rules += $r
    }
    return $rules
}

function Compare-CAHCValue {
    param($Actual, $Expected, [string]$Operator = 'eq')
    switch ($Operator) {
        'eq' { return ($Actual -eq $Expected) }
        'ne' { return ($Actual -ne $Expected) }
        'gt' { return ($Actual -gt $Expected) }
        'lt' { return ($Actual -lt $Expected) }
        'ge' { return ($Actual -ge $Expected) }
        'le' { return ($Actual -le $Expected) }
        'contains' { return ($Actual -like "*${Expected}*") }
        'regex' { return ($Actual -match $Expected) }
        default { return ($Actual -eq $Expected) }
    }
}

function Test-CAHCRule {
    [CmdletBinding()] param([pscustomobject]$Rule)
    $res = [ordered]@{
        Id=$Rule.id; Title=$Rule.title; Component=(@($Rule.appliesTo)|Select-Object -First 1); Severity=$Rule.severity
        Status='Skipped'; Actual=$null; Expected=$Rule.expected; Tags=$Rule.tags -join ','; Applicable=$Rule.Applicable
        Error=$null
    }
    if (-not $Rule.Applicable) { return [pscustomobject]$res }
    try {
        switch ($Rule.type) {
            'registry' {
                $reg = Get-ItemProperty -Path $Rule.path -ErrorAction Stop
                $allOk = $true
                $actualMap = @{}
                foreach ($k in $Rule.expected.PSObject.Properties.Name) {
                    $v = $reg.$k
                    $actualMap[$k] = $v
                    if (-not (Compare-CAHCValue -Actual $v -Expected $Rule.expected.$k -Operator ($Rule.operator?$Rule.operator:'eq'))) { $allOk = $false }
                }
                $res['Actual'] = $actualMap
                $res['Status'] = ($allOk ? 'Pass' : 'Fail')
            }
            'service' {
                $svc = Get-Service -Name $Rule.serviceName -ErrorAction Stop
                $statusOk = $true
                if ($Rule.expectedStatus) { $statusOk = (Compare-CAHCValue $svc.Status.ToString() $Rule.expectedStatus 'eq') }
                if ($Rule.expectedStartType) {
                    $wm = Get-WmiObject Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction Stop
                    $statusOk = $statusOk -and (Compare-CAHCValue $wm.StartMode $Rule.expectedStartType 'eq')
                }
                $res['Actual'] = @{ Status=$svc.Status.ToString() }
                $res['Status'] = ($statusOk ? 'Pass' : 'Fail')
            }
            'command' {
                $out = Invoke-Expression $Rule.command
                $res['Actual'] = $out
                $op = ($Rule.operator ? $Rule.operator:'eq')
                $ok = Compare-CAHCValue -Actual $out -Expected $Rule.expected -Operator $op
                $res['Status'] = ($ok ? 'Pass' : 'Fail')
            }
            'iisAppPool' {
                if (-not (Get-Module -ListAvailable -Name WebAdministration)) { $res['Status']='Skipped'; $res['Error']='WebAdministration module not available'; break }
                Import-Module WebAdministration -ErrorAction SilentlyContinue
                $state = (Get-WebAppPoolState -Name $Rule.poolName).Value
                $res['Actual'] = $state
                $res['Status'] = (Compare-CAHCValue $state $Rule.expectedStatus 'eq') ? 'Pass':'Fail'
            }
            'iisBinding' {
                if (-not (Get-Module -ListAvailable -Name WebAdministration)) { $res['Status']='Skipped'; $res['Error']='WebAdministration module not available'; break }
                Import-Module WebAdministration -ErrorAction SilentlyContinue
                $binds = Get-WebBinding -Name $Rule.site -ErrorAction Stop | Where-Object { $_.protocol -eq $Rule.protocol }
                $has = ($binds.Count -gt 0)
                $res['Actual'] = @{ hasBinding=$has; count=$binds.Count }
                $res['Status'] = (Compare-CAHCValue $has $Rule.expected 'eq') ? 'Pass':'Fail'
            }
            'file' {
                $exists = Test-Path -LiteralPath $Rule.path
                $res['Actual'] = @{ exists=$exists }
                $res['Status'] = (Compare-CAHCValue $exists $Rule.expected 'eq') ? 'Pass':'Fail'
            }
            'port' {
                $host = if ($Rule.host) { $Rule.host } else { 'localhost' }
                $p = Test-NetConnection -ComputerName $host -Port $Rule.port -WarningAction SilentlyContinue
                $ok = $p.TcpTestSucceeded
                $res['Actual'] = @{ success=$ok; latencyMs=$p.PingReplyDetails.RoundtripTime }
                $res['Status'] = (Compare-CAHCValue $ok $Rule.expected 'eq') ? 'Pass':'Fail'
            }
            default {
                $res['Error'] = "Unsupported type: $($Rule.type)"; $res['Status']='Skipped'
            }
        }
    } catch {
        $res['Status']='Error'; $res['Error'] = $_.Exception.Message
    }
    return [pscustomobject]$res
}

function Invoke-CAHCRules {
    [CmdletBinding()] param([array]$Rules)
    $results = foreach ($r in $Rules) { Test-CAHCRule -Rule $r }
    return ,$results
}

function Get-CAHCScore {
    [CmdletBinding()] param([array]$Results)
    $weights = @{ low=1; medium=2; high=3; critical=5 }
    $applicable = $Results | Where-Object { $_.Applicable -ne $false -and $_.Status -ne 'Skipped' }
    $possible = 0; $achieved = 0
    foreach ($r in $applicable) {
        $w = $weights[[string]$r.Severity]
        if (-not $w) { $w = 2 }
        $possible += $w
        if ($r.Status -eq 'Pass') { $achieved += $w }
    }
    if ($possible -eq 0) { return 100 }
    return [math]::Round(($achieved / $possible) * 100,2)
}

function Export-CAHCResults {
    [CmdletBinding()] param(
        [array]$Results,
        [double]$Score,
        [string[]]$Formats = @('Table'),
        [string]$OutDir = './out',
        [string[]]$Profile
    )
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

    if ($Formats -contains 'Table') {
        $Results | Sort-Object Status, Severity | Format-Table -AutoSize | Out-String | Set-Content -Path (Join-Path $OutDir 'results.txt')
        $Results | Sort-Object Status, Severity | Format-Table -AutoSize
    }
    if ($Formats -contains 'Json') {
        $obj = [ordered]@{ generated=(Get-Date); profile=($Profile -join ','); score=$Score; results=$Results }
        $obj | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $OutDir 'results.json')
    }
    if ($Formats -contains 'Csv') {
        $Results | Export-Csv -NoTypeInformation -Path (Join-Path $OutDir 'results.csv')
    }
    if ($Formats -contains 'Html') {
        $tpl = Get-Content -Raw -Path (Join-Path $PSScriptRoot '..' 'templates' 'report.html')
        $rows = ''
        foreach ($r in $Results) {
            $cls = 'skipped'
            if ($r.Status -eq 'Pass') { $cls = 'pass' }
            elseif ($r.Status -eq 'Fail') { $cls = 'fail' }
            $sev = [string]$r.Severity
            $rows += "<tr class='$cls'><td>$($r.Id)</td><td>$($r.Title)</td><td>$($r.Status)</td><td><span class='pill $sev'>$sev</span></td><td><pre>$([string]::Join('',($r.Actual | ConvertTo-Json -Depth 4)))</pre></td><td><pre>$([string]::Join('',($r.Expected | ConvertTo-Json -Depth 4)))</pre></td><td>$($r.Component)</td><td>$($r.Tags)</td></tr>"
        }
        $html = $tpl.Replace('{{generated}}',(Get-Date)).Replace('{{profile}}',($Profile -join ', ')).Replace('{{score}}', $Score).Replace('{{rows}}',$rows)
        $html | Set-Content -Path (Join-Path $OutDir 'results.html')
    }
}

Export-ModuleMember -Function *