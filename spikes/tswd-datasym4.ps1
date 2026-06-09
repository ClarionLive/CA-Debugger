# Phase 3 item-4 spike part 4: systematic framing of the +0x2C symbol-record region.
# Find EVERY strictly-valid nameRef u32 in the region, then derive record framing from
# the byte contexts (histogram of bytes at fixed offsets before the nameRef) and from
# the deltas between consecutive hits inside one scope block.
$Exe = "C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses\clbrws.exe"
$b = [System.IO.File]::ReadAllBytes($Exe)
$base = 0x16CE00
function U32([int]$r) { [BitConverter]::ToUInt32($b, $base + $r) }
$symPool = U32 0x20; $symNameArr = U32 0x28; $tbl2C = U32 0x2C; $tbl34 = U32 0x34
$poolLen = $symNameArr - $symPool

# index every NUL-preceded printable pool string start for strict ref validation
$valid = New-Object 'System.Collections.Generic.HashSet[uint32]'
$p = $symPool
while ($p -lt $symNameArr) {
    $s = $base + $p; $e = $s
    while ($e -lt $b.Length -and $b[$e] -ne 0) { $e++ }
    if ($e -gt $s) { [void]$valid.Add([uint32]($p - $symPool)) }
    $p += ($e - $s) + 1
}
"pool strings: $($valid.Count)"

function NameOf([uint32]$rel) {
    $s = $base + $symPool + [int]$rel; $e = $s
    while ($b[$e] -ne 0) { $e++ }
    [Text.Encoding]::ASCII.GetString($b, $s, $e - $s)
}

# scan T2C region for u32 values that are strictly-valid pool refs (>= 8 chars cuts noise)
$hits = New-Object Collections.Generic.List[object]
for ([int]$i = $tbl2C; $i -lt $tbl34 - 4; $i++) {
    [uint32]$v = [BitConverter]::ToUInt32($b, $base + $i)
    if ($v -lt 1 -or $v -ge $poolLen) { continue }
    if (-not $valid.Contains($v)) { continue }
    $hits.Add([pscustomobject]@{ Off = $i; Ref = $v })
}
"strict nameRef hits in T2C: $($hits.Count)"

# histogram of the byte 5 before and 1 before each hit (tag candidates)
$h5 = @{}; $h1 = @{}
foreach ($h in $hits) {
    $t5 = $b[$base + $h.Off - 5]; $t1 = $b[$base + $h.Off - 1]
    if (-not $h5.ContainsKey($t5)) { $h5[$t5] = 0 }; $h5[$t5]++
    if (-not $h1.ContainsKey($t1)) { $h1[$t1] = 0 }; $h1[$t1]++
}
"`nbyte at hit-5 (tag if {u8 tag, u32 link, u32 nameRef}):"
$h5.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object { "  0x{0:X2}: {1}" -f $_.Key, $_.Value }
"`nbyte at hit-1 (tag if {u8 tag, u32 nameRef}):"
$h1.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object { "  0x{0:X2}: {1}" -f $_.Key, $_.Value }

# deltas between consecutive hits (record stride candidates)
$d = @{}
for ($i = 1; $i -lt $hits.Count; $i++) {
    $delta = $hits[$i].Off - $hits[$i-1].Off
    if ($delta -le 64) { if (-not $d.ContainsKey($delta)) { $d[$delta] = 0 }; $d[$delta]++ }
}
"`nconsecutive-hit deltas (<=64):"
$d.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 12 | ForEach-Object { "  {0,3}: {1}" -f $_.Key, $_.Value }

# sample a run of consecutive hits with the most common delta and dump aligned records
$best = ($d.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Key
"`nmost common stride: $best — sample aligned records:"
$shown = 0
for ($i = 1; $i -lt $hits.Count -and $shown -lt 14; $i++) {
    if ($hits[$i].Off - $hits[$i-1].Off -ne $best) { continue }
    $o = $hits[$i].Off
    $rec = ""
    for ($j = -5; $j -lt $best - 5; $j++) { $rec += "{0:X2} " -f $b[$base + $o + $j] }
    "  0x{0:X6}: {1}  {2}" -f ($o - 5), $rec, (NameOf $hits[$i].Ref)
    $shown++
}
