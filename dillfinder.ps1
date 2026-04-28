# Check DLLs loaded into javaw.exe (possible injection traces)

$javawProcs = Get-Process javaw -ErrorAction SilentlyContinue

foreach ($proc in $javawProcs) {
try {
foreach ($mod in $proc.Modules) {
$path = $mod.FileName
if (-not $path) { continue }

```
        $sig = Sig $path
        if ($sig -ne "Valid" -or IsBadPath $path) {
            $results += [PSCustomObject]@{
                Name = $mod.ModuleName
                Path = $path
                Sig  = $sig
            }
        }
    }
} catch {}
```

}

$results = $results | Sort-Object Path -Unique

if ($results) {
$results | Out-GridView -Title "Suspicious EXEs / DLLs (javaw)"
}
