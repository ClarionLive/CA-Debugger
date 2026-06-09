$Exe="C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses\clbrws.exe"
$b=[System.IO.File]::ReadAllBytes($Exe); $base=0x16CC00
$symAddr=[BitConverter]::ToUInt32($b,$base+0x1C); $symPool=[BitConverter]::ToUInt32($b,$base+0x20)
$span=$symPool-$symAddr
"+0x1C table [0x{0:X},0x{1:X}) span {2}B / 8 = {3} recs" -f $symAddr,$symPool,$span,[math]::Floor($span/8)
# scan as 8-byte {u32 rva, u16 line, u16 mod}; report sorted? and modIdx for known addresses
$prev=0;$resets=0;$ntext=0;$tot=0
$modForRva=@{}
for([int]$o=$symAddr;$o+8 -le $symPool;$o+=8){
  [uint32]$rva=[BitConverter]::ToUInt32($b,$base+$o); $line=[BitConverter]::ToUInt16($b,$base+$o+4); $mod=[BitConverter]::ToUInt16($b,$base+$o+6)
  $tot++
  if($rva -ge 0x1000 -and $rva -lt 0xE0000){$ntext++}
  if($rva -lt $prev){$resets++}; $prev=$rva
  foreach($t in 0x2EDE0,0x31F68,0x2F70C,0x2EE2F,0x33594){ if($rva -eq $t){ "  rva 0x{0:X} -> line {1}  mod {2}" -f $rva,$line,$mod } }
}
"`ntotal recs {0}, in-text {1} ({2}%), rva-resets {3}" -f $tot,$ntext,[math]::Round(100*$ntext/$tot,1),$resets
# Collect distinct modIdx and a sample rva range for each (first/last rva seen)
"`n=== modIdx -> rva range (first 20 modIdx) ==="
$mm=@{}
for([int]$o=$symAddr;$o+8 -le $symPool;$o+=8){
  [uint32]$rva=[BitConverter]::ToUInt32($b,$base+$o); $mod=[BitConverter]::ToUInt16($b,$base+$o+6)
  if($rva -lt 0x1000 -or $rva -ge 0xE0000){continue}
  if(-not $mm.ContainsKey($mod)){ $mm[$mod]=[pscustomobject]@{Lo=$rva;Hi=$rva;N=0} }
  if($rva -lt $mm[$mod].Lo){$mm[$mod].Lo=$rva}; if($rva -gt $mm[$mod].Hi){$mm[$mod].Hi=$rva}; $mm[$mod].N++
}
foreach($k in ($mm.Keys|Sort-Object|Select -First 45)){ "  mod {0,3}: rva 0x{1:X6}..0x{2:X6}  n={3}" -f $k,$mm[$k].Lo,$mm[$k].Hi,$mm[$k].N }
