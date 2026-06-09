$Exe="C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses\clbrws.exe"
$b=[System.IO.File]::ReadAllBytes($Exe); $base=0x16CC00; $blen=$b.Length
function U32($r){[BitConverter]::ToUInt32($b,$base+$r)}
$modArr=U32 0x08;$modPool=U32 0x0C;$symPool=U32 0x20;$symNameArr=U32 0x28;$symAddr=U32 0x1C
$poolLen=$symNameArr-$symPool
$names=New-Object Collections.Generic.List[string]
for([int]$o=$modArr;$o+4 -le $modPool;$o+=4){ $no=U32 $o;$s=$base+$modPool+[int]$no;$e=$s;while($b[$e]-ne 0){$e++};$names.Add([Text.Encoding]::ASCII.GetString($b,$s,$e-$s)) }
$bk=@{}; for([int]$i=0;$i -lt 61;$i++){ $v=U32 ($symNameArr+$i*4); if(-not $bk.ContainsKey($v)){$bk[$v]=$i} }
function NameAt([int]$rel){ if($rel -lt 1 -or $rel -ge $poolLen){return $null}; $s=$base+$symPool+$rel; if($b[$s-1] -ne 0){return $null}; if($b[$s] -lt 0x21 -or $b[$s] -ge 0x7F){return $null}; $e=$s; while($b[$e] -ge 0x20 -and $b[$e] -lt 0x7F){$e++}; if($b[$e] -ne 0){return $null}; [Text.Encoding]::ASCII.GetString($b,$s,$e-$s) }
$mm=@{}
for([int]$o=$symAddr;$o+8 -le $symPool;$o+=8){ [uint32]$rva=[BitConverter]::ToUInt32($b,$base+$o);$mod=[BitConverter]::ToUInt16($b,$base+$o+6); if($rva -lt 0x1000 -or $rva -ge 0xE0000){continue}; if(-not $mm.ContainsKey([int]$mod)){$mm[[int]$mod]=[pscustomobject]@{Lo=$rva;Hi=$rva}}; if($rva -lt $mm[[int]$mod].Lo){$mm[[int]$mod].Lo=$rva};if($rva -gt $mm[[int]$mod].Hi){$mm[[int]$mod].Hi=$rva} }
# proc-entry defs: {nameRef, rva, modBackref}, name = top-level proc (NAME@F[nn], no ::)
$procs=@{}; $seen=@{}
for([int]$i=$symNameArr;$i -lt $blen-$base-12;$i++){
  [uint32]$nr=[BitConverter]::ToUInt32($b,$base+$i); if($nr -ge $poolLen -or $nr -lt 1){continue}
  [uint32]$rva=[BitConverter]::ToUInt32($b,$base+$i+4); if($rva -lt 0x1000 -or $rva -ge 0xE0000){continue}
  [uint32]$mb=[BitConverter]::ToUInt32($b,$base+$i+8); if(-not $bk.ContainsKey($mb)){continue}
  $nm=NameAt $nr; if(-not $nm){continue}
  if($nm -notmatch '^[A-Z][A-Z0-9_]*@F[0-9]*$'){continue}   # top-level proc, exclude thunk/methods
  $key="$nm|$rva"; if($seen.ContainsKey($key)){continue}; $seen[$key]=1
  $mi=$bk[$mb]
  if(-not $procs.ContainsKey($mi)){$procs[$mi]=New-Object Collections.Generic.List[object]}
  $procs[$mi].Add([pscustomobject]@{Name=($nm -replace '@F.*$',''); Rva=$rva})
}
@"
TSWD proc-symbol decode  (clbrws.exe) -- DETERMINISTIC modIdx -> proc + .clw
============================================================================
Symbol DEFINITION record (byte-granular, NOT 4-aligned) = 12 bytes LE:
   { u32 nameRef(pool-rel, NUL-preceded) ; u32 entryRVA ; u32 moduleBackref }
   moduleBackref == one of the 61 values in the +0x28 array; its index = MODULE index.
KEY RESULT: that module index EQUALS the +0x1C moduleIdx AND the +0x08 name-array index.
   => modIdx -> .clw name is TRIVIAL: names[modIdx]. No content-matching needed.
   (verified: SELECTJOBS@F->0x48D5C->mod37=clbrws011 ; BROWSEAUTHORSEIP@F->0x32D64->mod29=clbrws003)
SEMANTIC: generated proc modules carry exactly 1 top-level proc (1:1); the main module
   (clbrws.clw) carries several; library modules carry class methods (0 top-level procs).
Note: entryRVA (proc symbol) may be ABOVE the modIdx region Lo -- Clarion emits some proc
   code (init/embed/cold) below the named entry. Use +0x1C records (filtered by modIdx) for
   line<->addr; use entryRVA as the proc's canonical start.

modIdx  .clw(names[modIdx])   procDefCount  procName(entryRVA)   regionLo..Hi(+0x1C)
"@
foreach($k in ($procs.Keys|Sort-Object)){
  $cl = if($k -lt $names.Count){$names[$k]}else{"?"}
  $lst = ($procs[$k] | Sort-Object Rva | ForEach-Object {"{0}(0x{1:X})" -f $_.Name,$_.Rva}) -join ", "
  $reg = if($mm.ContainsKey($k)){"0x{0:X6}..0x{1:X6}" -f $mm[$k].Lo,$mm[$k].Hi}else{"(no +0x1C)"}
  "{0,5}   {1,-20} {2,6}        {3,-22} {4}" -f $k,$cl,$procs[$k].Count,$lst,$reg
}
