# Run by the collector for the Microsoft Teams module: connects with the two
# access tokens the collector obtained, runs each Get- cmdlet asked for, and
# writes one JSON document to standard output:
#   { "<cmdlet>": { "items": [ ... ] } | { "error": "..." } }
# Nothing is passed on the command line: tokens come in the environment.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$out = [ordered]@{}
try {
    Import-Module MicrosoftTeams
    Connect-MicrosoftTeams -AccessTokens @($env:ACD_GRAPH_TOKEN, $env:ACD_TEAMS_TOKEN) | Out-Null
}
catch {
    @{ '*' = @{ error = "connecting to Microsoft Teams: $($_.Exception.Message)" } } | ConvertTo-Json -Compress
    exit 0
}
foreach ($cmdlet in ($env:ACD_CMDLETS -split ',')) {
    # Only the read cmdlets of the Teams module, whatever is asked for.
    if ($cmdlet -notmatch '^Get-Cs[A-Za-z]+$') { continue }
    try {
        $out[$cmdlet] = @{ items = @(& $cmdlet | Select-Object -Property * -ExcludeProperty Key, ScopeClass, Anchor, TypedIdentity, Element, XsAnyElements, XsAnyAttributes, DataSource) }
    }
    catch {
        $out[$cmdlet] = @{ error = "$($_.Exception.Message)" }
    }
}
try { Disconnect-MicrosoftTeams -Confirm:$false | Out-Null } catch { }
$out | ConvertTo-Json -Depth 12 -Compress
