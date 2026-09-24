# Phase 3 item-5 spike: pin the +0x2C pointer convention and walk one record's children.
# Anchor: JOBS$JOB:RECORD tag-04 record at blob 0xDF180 (link 0x5740E -> base = 0x87D72).
# Its type info: 00 08 <u32 size=0x37> <u32 childCount=4?> then 4 u32 child pointers.
# Goal: resolve each child pointer to a tag-0C field record and print
#   {fieldName, offsetInRecord, typeByte, size} — expect the 4 JOB: fields covering 0x37 bytes.
$Exe = "C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses\clbrws.exe"
$b = [System.IO.File]::ReadAllBytes($Exe)
$base = 0x16CE00
function U32([int]$r) { [BitConverter]::ToUInt32($b, $base + $r) }
$symPool = U32 0x20; $symNameArr = U32 0x28
$poolLen = $symNameArr - $symPool

function NameOf([uint32]$rel) {
    if ($rel -lt 1 -or $rel -ge $poolLen) { return "(bad ref 0x{0:X})" -f $rel }
    $s = $base + $symPool + [int]$rel; $e = $s
    while ($b[$e] -ne 0) { $e++ }
    [Text.Encoding]::ASCII.GetString($b, $s, $e - $s)
}

# --- locate the JOBS$JOB:RECORD tag-04 record by scanning for nameRef 0x3D2 with tag 04 ---
# (from datasym5: record at 0xDF180: 04 | 0E 74 05 00 | D2 03 00 00 | F4 D1 0C 00 | 66 6C 05 00 | 00 08 37 ...)
$recOff = 0xDF180
"anchor record bytes:"
$hex = ""
for ($i = 0; $i -lt 48; $i++) { $hex += "{0:X2} " -f $b[$base + $recOff + $i] }
"  0x{0:X6}: {1}" -f $recOff, $hex

[uint32]$link = U32 ($recOff + 1)
$linkBase = $recOff - $link
"linkBase from anchor = 0x{0:X6}  (recOff 0x{1:X6} - link 0x{2:X6})" -f $linkBase, $recOff, $link

# record layout: tag@+0, link@+1, nameRef@+5, rva@+9, backref@+13 → type info starts @+17:
# expect 00 08 <size u32> <count u32> <child u32 x count>
$t0 = $b[$base + $recOff + 17]; $t1 = $b[$base + $recOff + 18]
[uint32]$size = U32 ($recOff + 19)
[uint32]$count = U32 ($recOff + 23)
"typeBytes: {0:X2} {1:X2}  size=0x{2:X} ({2})  childCount={3}" -f $t0, $t1, $size, $count

$children = @()
for ($i = 0; $i -lt [Math]::Min($count, 16); $i++) { $children += U32 ($recOff + 27 + $i*4) }
"child ptrs: " + (($children | ForEach-Object { "0x{0:X6}" -f $_ }) -join " ")

# --- resolve children against several base candidates; pick the one where every target
#     starts with a plausible tag byte (04/0C) and a valid nameRef at +5 ---
foreach ($cb in ($linkBase-2), ($linkBase-1), $linkBase, ($linkBase+1), ($linkBase+2)) {
    $ok = $true
    $out = New-Object Collections.Generic.List[string]
    foreach ($c in $children) {
        $t = $cb + $c
        $tag = $b[$base + $t]
        [uint32]$nr = U32 ($t + 1)
        $nm = $null
        if ($nr -ge 1 -and $nr -lt $poolLen) { $nm = NameOf $nr }
        if (($tag -ne 0x04 -and $tag -ne 0x0C) -or -not $nm -or $nm.StartsWith("(bad")) { $ok = $false }
        $out.Add(("    tag {0:X2} @0x{1:X6}  nameRef 0x{2:X5} -> {3}" -f $tag, $t, $nr, $nm))
    }
    "`nbase 0x{0:X6}: {1}" -f $cb, ($(if ($ok) { "ALL CHILDREN VALID" } else { "invalid" }))
    $out | ForEach-Object { $_ }
    if ($ok) {
        "  field details (tag | link | name | offset | parent | trailing type bytes):"
        foreach ($c in $children) {
            $t = $cb + $c
            $tag = $b[$base + $t]
            [uint32]$lk = U32 ($t + 1)
            [uint32]$nr = U32 ($t + 5)
            [int]$fOff = [BitConverter]::ToInt32($b, $base + $t + 9)
            [uint32]$par = U32 ($t + 13)
            $trail = ""
            for ($j = 17; $j -lt 26; $j++) { $trail += "{0:X2} " -f $b[$base + $t + $j] }
            "    {0:X2} | link 0x{1:X6} | {2,-22} | off {3,3} | parent 0x{4:X6} | {5}" -f $tag, $lk, (NameOf $nr), $fOff, $par, $trail
        }
    }
}
