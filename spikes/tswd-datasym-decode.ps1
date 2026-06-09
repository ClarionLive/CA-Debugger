# Phase 3 item-4 spike: find DATA-symbol records in the TSWD blob.
# Lead: TOC +0x30 says 2236 symbols; the proc scan (.text-filtered) finds 2057.
# Hypothesis: the ~179 missing are the SAME 12-byte {nameRef, rva, moduleBackref}
# records with the RVA pointing into a DATA section (globals like JOB:JOBID).
$Exe = "C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses\clbrws.exe"
$b = [System.IO.File]::ReadAllBytes($Exe)

# --- PE walk: find the debug directory (don't hardcode the blob offset; builds move it) ---
$peOff = [BitConverter]::ToInt32($b, 0x3C)
$numSec = [BitConverter]::ToUInt16($b, $peOff + 6)
$optOff = $peOff + 24
$ddOff = $optOff + 96          # data directories (PE32)
$dbgRva = [BitConverter]::ToUInt32($b, $ddOff + 6*8)
# section table: map RVA->file + collect section ranges
$secOff = $optOff + [BitConverter]::ToUInt16($b, $peOff + 20)
$secs = @()
for ($i = 0; $i -lt $numSec; $i++) {
    $o = $secOff + $i*40
    $secs += [pscustomobject]@{
        Name    = [Text.Encoding]::ASCII.GetString($b, $o, 8).TrimEnd([char]0)
        VSize   = [BitConverter]::ToUInt32($b, $o+8)
        Rva     = [BitConverter]::ToUInt32($b, $o+12)
        RawSize = [BitConverter]::ToUInt32($b, $o+16)
        RawPtr  = [BitConverter]::ToUInt32($b, $o+20)
    }
}
"PE sections:"
$secs | ForEach-Object { "  {0,-8} RVA 0x{1:X6}..0x{2:X6}  raw 0x{3:X6}" -f $_.Name, $_.Rva, ($_.Rva + $_.VSize), $_.RawPtr }
function RvaToFile([uint32]$rva) {
    foreach ($s in $secs) { if ($rva -ge $s.Rva -and $rva -lt $s.Rva + $s.VSize) { return $s.RawPtr + ($rva - $s.Rva) } }
    return -1
}
function SecOf([uint32]$rva) {
    foreach ($s in $secs) { if ($rva -ge $s.Rva -and $rva -lt $s.Rva + $s.VSize) { return $s.Name } }
    return "?"
}
$dbgFile = RvaToFile $dbgRva
$base = [BitConverter]::ToUInt32($b, $dbgFile + 24)   # IMAGE_DEBUG_DIRECTORY.PointerToRawData
"debug blob file offset: 0x{0:X}" -f $base
$blen = $b.Length

function U32([int]$r) { [BitConverter]::ToUInt32($b, $base + $r) }
$modArr = U32 0x08; $modPool = U32 0x0C; $symPool = U32 0x20; $symNameArr = U32 0x28
$modCount = U32 0x24; $tbl2C = U32 0x2C; $symCount = U32 0x30; $tbl34 = U32 0x34
$poolLen = $symNameArr - $symPool
"TOC: modCount=$modCount symCount=$symCount tbl2C=0x{0:X} tbl34=0x{1:X} pool=[0x{2:X},0x{3:X})" -f $tbl2C, $tbl34, $symPool, $symNameArr

$names = New-Object Collections.Generic.List[string]
for ([int]$o = $modArr; $o + 4 -le $modPool; $o += 4) {
    $no = U32 $o; $s = $base + $modPool + [int]$no; $e = $s
    while ($b[$e] -ne 0) { $e++ }
    $names.Add([Text.Encoding]::ASCII.GetString($b, $s, $e - $s))
}
$bk = @{}
for ([int]$i = 0; $i -lt $modCount; $i++) { $v = U32 ($symNameArr + $i*4); if (-not $bk.ContainsKey($v)) { $bk[$v] = $i } }

function NameAt([int]$rel) {
    if ($rel -lt 1 -or $rel -ge $poolLen) { return $null }
    $s = $base + $symPool + $rel
    if ($b[$s-1] -ne 0) { return $null }
    if ($b[$s] -lt 0x21 -or $b[$s] -ge 0x7F) { return $null }
    $e = $s
    while ($b[$e] -ge 0x20 -and $b[$e] -lt 0x7F) { $e++ }
    if ($b[$e] -ne 0) { return $null }
    [Text.Encoding]::ASCII.GetString($b, $s, $e - $s)
}

# --- scan WITHOUT the .text filter; classify each candidate by the section its RVA lands in ---
$imgHi = ($secs | ForEach-Object { $_.Rva + $_.VSize } | Measure-Object -Maximum).Maximum
$seen = @{}
$bySec = @{}
$dataRecs = New-Object Collections.Generic.List[object]
for ([int]$i = $symNameArr; $i -lt $blen - $base - 12; $i++) {
    [uint32]$nr = [BitConverter]::ToUInt32($b, $base + $i); if ($nr -ge $poolLen -or $nr -lt 1) { continue }
    [uint32]$rva = [BitConverter]::ToUInt32($b, $base + $i + 4); if ($rva -lt 0x1000 -or $rva -ge $imgHi) { continue }
    [uint32]$mb = [BitConverter]::ToUInt32($b, $base + $i + 8); if (-not $bk.ContainsKey($mb)) { continue }
    $nm = NameAt $nr; if (-not $nm) { continue }
    if ($nm.StartsWith("__thunk.")) { continue }
    $key = "$nm|$rva"; if ($seen.ContainsKey($key)) { continue }; $seen[$key] = 1
    $sec = SecOf $rva
    if (-not $bySec.ContainsKey($sec)) { $bySec[$sec] = 0 }
    $bySec[$sec]++
    if ($sec -ne ".text") {
        $dataRecs.Add([pscustomobject]@{ Name = $nm; Rva = $rva; ModIdx = $bk[$mb]; Sec = $sec; BlobOff = $i })
    }
}
""
"records by section:"
$bySec.GetEnumerator() | Sort-Object Name | ForEach-Object { "  {0,-8} {1,5}" -f $_.Key, $_.Value }
""
"NON-.text records ($($dataRecs.Count)):"
$dataRecs | Sort-Object Rva | ForEach-Object {
    $mod = if ($_.ModIdx -lt $names.Count) { $names[$_.ModIdx] } else { "?" }
    "  0x{0:X6} {1,-6} mod{2,-3} {3,-18} {4}" -f $_.Rva, $_.Sec, $_.ModIdx, $mod, $_.Name
}
