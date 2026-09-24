$Exe = "C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses\clbrws.exe"
$b = [System.IO.File]::ReadAllBytes($Exe)
$base = 0x16CC00
# clbrws013 chunk 0x1F90..0x21F0 phase 2 — find lines 315..325
Write-Host "=== line 315..325 inside clbrws013 chunk (ph2) — where does SelectSort L317 really map? ==="
for($p=$base+0x1F90+2; $p+6 -le $base+0x21F0; $p+=6){
  $ln=[BitConverter]::ToUInt16($b,$p); $rva=[BitConverter]::ToUInt32($b,$p+2)
  if($ln -ge 315 -and $ln -le 325){ "  line {0}  rva 0x{1:X}  (VA 0x{2:X})" -f $ln,$rva,(0x400000+$rva) }
}
# Does clbrws010 end at line 170 continuing into 011's 171? clbrws010 0x16ED..0x1985 ph5
Write-Host "`n=== clbrws010 chunk (ph5) TAIL — does it run up to 170? ==="
$r=New-Object Collections.Generic.List[object]
for($p=$base+0x16ED+5;$p+6 -le $base+0x1985;$p+=6){ $r.Add([pscustomobject]@{Line=[BitConverter]::ToUInt16($b,$p);Rva=[BitConverter]::ToUInt32($b,$p+2)}) }
($r | Select -Last 8 | ForEach-Object {"{0}@0x{1:X}" -f $_.Line,$_.Rva}) -join "  "
# Trace the big run forward past 015: clbrws016,017 — does it reach ~1004 then reset?
Write-Host "`n=== clbrws016/017 heads+tails — does the 17.. run reach ~1004? ==="
function HT($name,$ss,$ee,$ph){
  $r=New-Object Collections.Generic.List[object]
  for($p=$base+$ss+$ph;$p+6 -le $base+$ee;$p+=6){ $r.Add([pscustomobject]@{Line=[BitConverter]::ToUInt16($b,$p);Rva=[BitConverter]::ToUInt32($b,$p+2)}) }
  Write-Host ("  {0}: HEAD {1}  ... TAIL {2}" -f $name,(($r|Select -First 3|%{"{0}@0x{1:X}" -f $_.Line,$_.Rva}) -join " "),(($r|Select -Last 3|%{"{0}@0x{1:X}" -f $_.Line,$_.Rva}) -join " "))
}
# need phases for 016,017 — brute pick best
function BestPhase($ss,$ee){ $bp=0;$bg=-1; for($ph=0;$ph -lt 6;$ph++){ $g=0; for($p=$base+$ss+$ph;$p+6 -le $base+$ee;$p+=6){ $ln=[BitConverter]::ToUInt16($b,$p);$rv=[BitConverter]::ToUInt32($b,$p+2); if($ln -ge 1 -and $ln -lt 20000 -and $rv -ge 0x1000 -and $rv -lt 0xE0000){$g++} }; if($g -gt $bg){$bg=$g;$bp=$ph} }; $bp }
# module ranges 016=idx42,017=idx43
foreach($i in 40,41,42,43){
  $ro=$base+0x444+$i*8; $ss=[BitConverter]::ToUInt32($b,$ro); $ee=[BitConverter]::ToUInt32($b,$ro+4)
  $ph=BestPhase $ss $ee
  HT ("mod[$i] 0x{0:X}..0x{1:X} ph$ph" -f $ss,$ee) $ss $ee $ph
}
