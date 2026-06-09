# Phase 3 item-4 spike part 2: where do app globals (JOB:JOBID etc.) live?
# (a) dump the +0x28 backref VALUES — are they blob offsets (module block keys)?
# (b) find the pool nameRef of known globals and search the whole blob for u32 refs to them
# (c) hexdump around whatever references we find
$Exe = "C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses\clbrws.exe"
$b = [System.IO.File]::ReadAllBytes($Exe)
$base = 0x16CE00; $blen = $b.Length; $blobLen = $blen - $base
function U32([int]$r) { [BitConverter]::ToUInt32($b, $base + $r) }
function U16([int]$r) { [BitConverter]::ToUInt16($b, $base + $r) }
$symPool = U32 0x20; $symNameArr = U32 0x28; $modCount = U32 0x24
$tbl2C = U32 0x2C; $tbl34 = U32 0x34
$poolLen = $symNameArr - $symPool
"blobLen=0x{0:X}  pool=[0x{1:X},0x{2:X})  tbl2C=0x{3:X}  tbl34=0x{4:X}" -f $blobLen, $symPool, $symNameArr, $tbl2C, $tbl34

"`n+0x28 backref values (61):"
$vals = for ([int]$i = 0; $i -lt $modCount; $i++) { U32 ($symNameArr + $i*4) }
$line = ""
for ($i = 0; $i -lt $vals.Count; $i++) { $line += ("{0,3}:0x{1:X6}  " -f $i, $vals[$i]); if (($i+1) % 5 -eq 0) { $line; $line = "" } }
if ($line) { $line }

# --- find pool offsets of interesting names ---
$targets = "JOB:JOBID", "JOB:RECORD", "BRW1::LASTSORTORDER", "GLOBALERRORS", "GLO:", "SAVEPATH"
"`nname-pool hits:"
$nameRefs = @{}
$p = $symPool
while ($p -lt $symNameArr) {
    $s = $base + $p; $e = $s
    while ($e -lt $blen -and $b[$e] -ne 0) { $e++ }
    if ($e -gt $s) {
        $nm = [Text.Encoding]::ASCII.GetString($b, $s, $e - $s)
        foreach ($t in $targets) {
            if ($nm -like "*$t*") {
                $rel = $p - $symPool
                "  rel 0x{0:X6}  {1}" -f $rel, $nm
                if (-not $nameRefs.ContainsKey($nm)) { $nameRefs[$nm] = $rel }
                break
            }
        }
    }
    $p += ($e - $s) + 1
}

# --- search the whole blob for u32 == nameRef of the first few hits ---
"`nblob-wide u32 references:"
foreach ($kv in ($nameRefs.GetEnumerator() | Select-Object -First 6)) {
    $nm = $kv.Key; [uint32]$ref = $kv.Value
    $hits = New-Object Collections.Generic.List[int]
    for ([int]$i = 0; $i -lt $blobLen - 4; $i++) {
        if ([BitConverter]::ToUInt32($b, $base + $i) -eq $ref) { $hits.Add($i) }
    }
    $where = ($hits | ForEach-Object {
        $reg = if ($_ -ge $tbl34) { "T34" } elseif ($_ -ge $tbl2C) { "T2C" } elseif ($_ -ge $symNameArr) { "BKA" } else { "lo" }
        "0x{0:X6}({1})" -f $_, $reg
    }) -join " "
    "  {0,-28} ref=0x{1:X5}  {2} hit(s): {3}" -f $nm, $ref, $hits.Count, $where
}
