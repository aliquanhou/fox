# Extract Ground Truth function ranges from MSVC linker .map files
# Independent of FOX — uses MSVC linker output as source of truth

$root = "C:\Users\Administrator\Doubao\chats\2026-09-08\new-chat-1\fox\tests\ground_truth"
$metaDir = Join-Path $root "metadata"
$expectedDir = Join-Path $root "expected"

if (-not (Test-Path $expectedDir)) { New-Item -ItemType Directory -Force -Path $expectedDir | Out-Null }

$mapFiles = Get-ChildItem (Join-Path $metaDir "*.map") | Sort-Object Name

foreach ($mapFile in $mapFiles) {
    $baseName = $mapFile.BaseName  # e.g. 01_linear_O0
    Write-Host "Processing $baseName..."

    # Parse map file for gt_* functions (CODE symbols, not $unwind$)
    $functions = @()
    $lines = Get-Content $mapFile.FullName
    foreach ($line in $lines) {
        # Match: 0001:00006280       gt_add                     0000000140007280 f   01_linear.obj
        if ($line -match '^\s*0001:([0-9A-Fa-f]+)\s+(gt_\w+)\s+([0-9A-Fa-f]+)\s+f\s') {
            $rva = [Convert]::ToInt64($matches[1], 16)
            $name = $matches[2]
            $va = [Convert]::ToInt64($matches[3], 16)
            $functions += [PSCustomObject]@{
                name = $name
                rva = $rva
                va = $va
            }
        }
    }

    # Sort by RVA and compute end = next function start
    $functions = $functions | Sort-Object rva
    for ($i = 0; $i - $functions.Count; $i++) {
        if ($i -lt $functions.Count - 1) {
            $functions[$i] | Add-Member -NotePropertyName end_rva -NotePropertyValue $functions[$i+1].rva
            $functions[$i] | Add-Member -NotePropertyName end_va -NotePropertyValue $functions[$i+1].va
        } else {
            # Last function: end unknown (mark as null)
            $functions[$i] | Add-Member -NotePropertyName end_rva -NotePropertyValue $null
            $functions[$i] | Add-Member -NotePropertyName end_va -NotePropertyValue $null
        }
    }

    # Build expected fixture
    $expectedFunctions = @()
    foreach ($f in $functions) {
        $expectedFunctions += [PSCustomObject]@{
            name = $f.name
            start_rva = "0x{0:X}" -f $f.rva
            start_va = "0x{0:X16}" -f $f.va
            end_rva = if ($f.end_rva) { "0x{0:X}" -f $f.end_rva } else { $null }
            end_va = if ($f.end_va) { "0x{0:X16}" -f $f.end_va } else { $null }
        }
    }

    $fixture = [PSCustomObject]@{
        sample_name = $baseName
        source_file = "$($baseName -replace '_O[02]$','').c"
        compiler = "MSVC"
        compiler_version = "19.44.35224"
        architecture = "x64"
        optimization = if ($baseName -match '_O0$') { "-O0 (/Od)" } else { "-O2 (/O2)" }
        expected_function_count = $functions.Count
        expected_functions = $expectedFunctions
        ground_truth_source = "MSVC linker .map file (independent of FOX)"
    }

    $json = $fixture | ConvertTo-Json -Depth 5
    $outPath = Join-Path $expectedDir "$baseName.json"
    $json | Out-File -FilePath $outPath -Encoding utf8
    Write-Host "  -> $($functions.Count) functions, saved to $baseName.json"
}

Write-Host "`nDone. Generated $(Get-ChildItem $expectedDir -Filter *.json | Measure-Object | Select-Object -ExpandProperty Count) expected fixtures."
