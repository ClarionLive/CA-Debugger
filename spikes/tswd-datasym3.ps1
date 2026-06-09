# Phase 3 item-4 spike part 3: hexdump around variable-name references inside the +0x2C
# region to recover the data-symbol record layout.
$Exe = "C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses\clbrws.exe"
$b = [System.IO.File]::ReadAllBytes($Exe)
$base = 0x16CE00
function U32([int]$r) { [BitConverter]::ToUInt32($b, $base + $r) }
$symPool = U32 0x20; $symNameArr = U32 0x28; $poolLen = $symNameArr - $symPool

function NameAt([uint32]$rel) {
    if ($rel -lt 1 -or $rel -ge $poolLen) { return $null }
    $s = $base + $symPool + [int]$rel
    if ($b[$s-1] -ne 0) { return $null }
    $e = $s
    while ($b[$e] -ge 0x20 -and $b[$e] -lt 0x7F) { $e++ }
    if ($b[$e] -ne 0 -or $e -eq $s) { return $null }
    [Text.Encoding]::ASCII.GetString($b, $s, $e - $s)
}

function HexDump([int]$off, [int]$before, [int]$after, [string]$title) {
    "== $title  (blob 0x{0:X6}, ref-field at +{1}) ==" -f $off, $before
    $start = $off - $before
    for ($row = 0; $row -lt ($before + $after) / 16; $row++) {
        $o = $start + $row * 16
        $hex = ""; $asc = ""
        for ($i = 0; $i -lt 16; $i++) {
            $v = $b[$base + $o + $i]
            $hex += "{0:X2} " -f $v
            $asc += if ($v -ge 0x20 -and $v -lt 0x7F) { [char]$v } else { "." }
            if ($i -eq 7) { $hex += " " }
        }
        $mark = if ($o -le $off -and $off -lt $o + 16) { " <-- ref" } else { "" }
        "  0x{0:X6}: {1} {2}{3}" -f $o, $hex, $asc, $mark
    }
}

# JOB:JOBID (ref 0x3E2): first hit near region start + one later
HexDump 0x088162 32 48 "JOB:JOBID hit #1"
HexDump 0x0F5516 32 48 "JOB:JOBID hit (mid)"
# BRW1::LASTSORTORDER (ref 0xB0D): first hit
HexDump 0x0E0A75 32 48 "BRW1::LASTSORTORDER hit #1"
# region opening bytes
HexDump 0x087D84 0 96 "tbl2C region start"
# SAVEPATH global (ref 0x7E84)
HexDump 0x08FBF8 32 48 "SAVEPATH hit"
