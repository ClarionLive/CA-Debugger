# decode-tswd.ps1
# Decodes and validates the Clarion 'TSWD' embedded debug blob from a Full-debug EXE.
# Locates the blob via the PE Debug Directory, parses the TOC header, and validates the
# two line-number tables (source-line<->address). Reports % of addresses landing in .text.
#
# Usage:  pwsh -File decode-tswd.ps1 -Exe "C:\path\to\app.exe"
#
# NOTE: the TOC sub-table offsets (line tables, pools) are read from the header, so this
# works on any TSWD blob — the 0x624 / 0x889A constants below are derived, not hard-coded.

param(
  [string]$Exe = "C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses\clbrws.exe"
)

$b = [System.IO.File]::ReadAllBytes($Exe)
$len = $b.Length
function RU16($abs){ [BitConverter]::ToUInt16($b,$abs) }
function RU32($abs){ [BitConverter]::ToUInt32($b,$abs) }

# --- PE basics ---
$peOff   = [BitConverter]::ToInt32($b,0x3C)
$optOff  = $peOff + 24
$imgBase = RU32 ($optOff + 28)
$numSec  = RU16 ($peOff + 6)
$optSize = RU16 ($peOff + 20)

# Data Directory index 6 = Debug Directory
$ddOff    = $optOff + 96 + (6*8)
$debugRVA = RU32 $ddOff

# section table -> RVA->file-offset, and .text range
$secOff = $optOff + $optSize
$secs = for($i=0;$i -lt $numSec;$i++){
  $o = $secOff + $i*40
  [pscustomobject]@{
    Name = [System.Text.Encoding]::ASCII.GetString($b,$o,8).TrimEnd([char]0)
    VA=RU32 ($o+12); VS=RU32 ($o+8); Raw=RU32 ($o+20); RS=RU32 ($o+16)
  }
}
function RvaToOff($rva){ foreach($s in $secs){ if($rva -ge $s.VA -and $rva -lt ($s.VA+[math]::Max($s.VS,$s.RS))){ return $s.Raw + ($rva-$s.VA) } } -1 }
$text = $secs | Where-Object Name -eq '.text'
$textVA = $text.VA; $textEnd = $text.VA + $text.VS

# --- locate TSWD blob via the debug directory entry ---
$do   = RvaToOff $debugRVA
$type = RU32 ($do+12)
if($type -ne 0x44575354){ Write-Host "WARNING: debug type is 0x$('{0:X}' -f $type), expected 'TSWD' (0x44575354)" }
$base = RU32 ($do+24)        # PointerToRawData = blob file offset
$size = RU32 ($do+16)
Write-Host ("ImageBase=0x{0:X}  .text RVA 0x{1:X}..0x{2:X}" -f $imgBase,$textVA,$textEnd)
Write-Host ("TSWD blob @ file 0x{0:X}  size {1} bytes" -f $base,$size)

# --- TOC header ---
$tocLineA = RU32 ($base+0x14)   # line table A start (line-major)
$tocLineB = RU32 ($base+0x18)   # line table B start (addr-major)
$tocEndB  = RU32 ($base+0x1C)   # B end / next table
$modCount = RU32 ($base+0x24)
Write-Host ("TOC: lineTableA=0x{0:X}  lineTableB=0x{1:X}  endB=0x{2:X}  modules={3}" -f $tocLineA,$tocLineB,$tocEndB,$modCount)

function ParseTable($start,$end,$order){
  $r = New-Object System.Collections.Generic.List[object]
  $o = $start
  while($o+6 -le $end -and $base+$o+6 -le $len){
    if($order -eq 'LA'){ $line=RU16 ($base+$o); $rva=RU32 ($base+$o+2) }
    else               { $rva =RU32 ($base+$o); $line=RU16 ($base+$o+4) }
    $r.Add([pscustomobject]@{RVA=$rva;Line=$line}); $o+=6
  }
  ,$r
}
function Validate($name,$recs){
  $n=$recs.Count; $in=0
  foreach($x in $recs){ if($x.RVA -ge $textVA -and $x.RVA -lt $textEnd){$in++} }
  Write-Host ("{0}: {1} records, {2} in .text ({3}%)" -f $name,$n,$in,[math]::Round(100.0*$in/$n,1))
}

$A = ParseTable $tocLineA $tocLineB 'LA'
$B = ParseTable $tocLineB $tocEndB  'AL'
Validate "Line Table A {line,rva}" $A
Validate "Line Table B {rva,line}" $B

Write-Host "`nLine Table A (first 5):"
for($i=0;$i -lt 5 -and $i -lt $A.Count;$i++){ "  line {0,5} -> RVA 0x{1:X}  (VA 0x{2:X})" -f $A[$i].Line,$A[$i].RVA,($imgBase+$A[$i].RVA) }

# --- lookup helpers (what the engine will use) ---
function LineToAddr([int]$line){ ($A | Where-Object Line -eq $line | Select-Object -First 1).RVA }
function AddrToLine([uint32]$rva){
  $best=$null; foreach($x in $B){ if($x.RVA -le $rva){ $best=$x } else { break } }; if($best){$best.Line}
}
