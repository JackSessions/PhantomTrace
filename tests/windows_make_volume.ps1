# Creates a real NTFS volume with Windows itself (a fixed VHD), uses it the way a real volume is used,
# then detaches it so phantom_trace.py can read the .vhd as a raw disk image. Needs an elevated prompt.
param([string]$Vhd = "$env:TEMP\win.vhd", [string]$Letter = "T")
$ErrorActionPreference = 'Stop'
if (Test-Path $Vhd) { Remove-Item $Vhd -Force }
$tmp = New-TemporaryFile

function Run-DiskPart([string]$text) {
    Set-Content -Path $tmp -Value $text -Encoding ascii
    diskpart /s $tmp.FullName
    if ($LASTEXITCODE -ne 0) { throw "diskpart failed ($LASTEXITCODE)" }
}

Run-DiskPart @"
create vdisk file="$Vhd" maximum=128 type=fixed
select vdisk file="$Vhd"
attach vdisk
create partition primary
format fs=ntfs quick label=PTWIN
assign letter=$Letter
"@
Start-Sleep -Seconds 3

$root = "${Letter}:\"
$rng = New-Object System.Random 42
function Write-Random([string]$path, [int]$size) { $b = New-Object byte[] $size; $rng.NextBytes($b); [IO.File]::WriteAllBytes($path, $b) }

New-Item -ItemType Directory -Path "${root}a", "${root}a\b", "${root}c" | Out-Null
1..150 | ForEach-Object { Write-Random "${root}a\f$_.bin" ($rng.Next(100, 90000)) }
for ($i = 3; $i -le 150; $i += 3) { Remove-Item "${root}a\f$i.bin" }                       # deletions
1..300 | ForEach-Object { Set-Content "${root}c\t$_.txt" "tiny $_" }                       # many small (resident) files
1..40 | ForEach-Object { Write-Random "${root}a\b\g$_.bin" ($rng.Next(5000, 200000)) }
for ($i = 5; $i -le 40; $i += 5) { Copy-Item "${root}a\b\g$i.bin" "${root}a\b\h$i.bin"; Remove-Item "${root}a\b\g$i.bin" }
Write-Random "${root}big.dat" 8000000                                                    # large, likely multi-run
Add-Content -Path "${root}a\f1.bin" -Value "extra" -Stream hidden                          # an alternate data stream
Write-VolumeCache -DriveLetter $Letter

Run-DiskPart @"
select vdisk file="$Vhd"
detach vdisk
"@
Write-Host "Created $Vhd"
