# Phase 3 item-4 spike part 5: chase JOB:JOBID's parent pointer — does the parent
# (file/record) block carry the static base address of the JOBS record buffer?
# Record under test (from part 3, blob 0x0F5511):
#   0C | 9E D7 06 00 (link 0x6D79E) | E2 03 00 00 (JOB:JOBID) | 00 00 00 00 (offset 0)
#      | 17 D7 06 00 (parent 0x6D717) | 11 | 02 00 00 00
# Hypothesis: link/parent values are offsets relative to a fixed base near tbl2C.
$Exe = "C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses\clbrws.exe"
$b = [System.IO.File]::ReadAllBytes($Exe)
$base = 0x16CE00
function U32([int]$r) { [BitConverter]::ToUInt32($b, $base + $r) }
$symPool = U32 0x20; $symNameArr = U32 0x28; $tbl2C = U32 0x2C
$poolLen = $symNameArr - $symPool

function NameOf([uint32]$rel) {
    if ($rel -lt 1 -or $rel -ge $poolLen) { return "(bad)" }
    $s = $base + $symPool + [int]$rel; $e = $s
    while ($b[$e] -ne 0) { $e++ }
    [Text.Encoding]::ASCII.GetString($b, $s, $e - $s)
}
function HexDump([int]$off, [int]$len, [string]$title) {
    "== $title (blob 0x{0:X6}) ==" -f $off
    for ($row = 0; $row -lt $len / 16; $row++) {
        $o = $off + $row * 16
        $hex = ""; $asc = ""
        for ($i = 0; $i -lt 16; $i++) {
            $v = $b[$base + $o + $i]
            $hex += "{0:X2} " -f $v
            $asc += if ($v -ge 0x20 -and $v -lt 0x7F) { [char]$v } else { "." }
            if ($i -eq 7) { $hex += " " }
        }
        "  0x{0:X6}: {1} {2}" -f $o, $hex, $asc
    }
}

# candidate bases: the record-self evidence gave start-link = 0x87D72 (locals) / 0x87D73 (JOB rec).
# try both for the parent pointer and dump what's there.
foreach ($cb in 0x87D70, 0x87D71, 0x87D72, 0x87D73, 0x87D74, $tbl2C) {
    $t = $cb + 0x6D717
    HexDump ($t - 16) 64 ("parent 0x6D717 @ base 0x{0:X} -> 0x{1:X6}" -f $cb, $t)
    ""
}

# Also: JOBS$JOB:RECORD is in the pool (rel 0x3D2). Find u32 refs to it in T2C — the JOBS
# record-buffer block should reference that name and carry an address in .data/.cwtls
# (sections: .data 0xB3000..0xC825C, .cwtls 0xC9000..0xDF590).
$tbl34 = U32 0x34
"refs to JOBS`$JOB:RECORD (0x3D2) in T2C:"
for ([int]$i = $tbl2C; $i -lt $tbl34 - 4; $i++) {
    if ([BitConverter]::ToUInt32($b, $base + $i) -eq 0x3D2) {
        "  hit at 0x{0:X6}" -f $i
        HexDump ($i - 16) 64 "context"
    }
}
