#Requires -Version 5.1
<#
.SYNOPSIS
    Creates a labfw firewall VM on Hyper-V (hybrid mode: policy in Azure,
    firewall on the laptop). docs/PLAN.md section 8.8, README "Hybrid".

.DESCRIPTION
    Two-armed Ubuntu 24.04 VM (Generation 2, Secure Boot with the Microsoft
    UEFI CA template):

      eth0  WAN uplink on -WanSwitch (default 'Default Switch', DHCP)
      eth1  LAN on -LanSwitch (created as Internal or Private switch when
            missing), static -LanAddress; labfw is the default gateway and
            DNS server of the LAN clients

    The disk is the official Ubuntu cloud image for Azure/Hyper-V
    (ubuntu-24.04-server-cloudimg-amd64-azure.vhd.tar.gz from
    cloud-images.ubuntu.com), verified against SHA256SUMS (and its GPG
    signature with -VerifySignature when gpg.exe is available), extracted
    with the tar.exe that ships with Windows and converted to a dynamic
    VHDX (cached in -ImageCacheDir). cloud-init gets a NoCloud seed: a small
    FAT32 VHDX labelled CIDATA (New-VHD/Initialize-Disk/New-Partition/
    Format-Volume, no third-party tools) with user-data, meta-data and
    network-config. user-data is deploy/cloud-init/cloud-init.yaml with the
    same placeholders main.bicep renders (release tag, arch, repo, config,
    install-labfw.sh) plus the credential file (base64, /etc/labfw/credentials,
    0600; install-labfw.sh hands it to the labfw user).

    The Azure image restricts cloud-init to its Azure datasource
    (/etc/cloud/cloud.cfg.d/90_dpkg.cfg: datasource_list: [ Azure ]), which
    only the kernel command line overrides. The script therefore edits the
    GRUB stub on the image's EFI system partition (FAT32, writable from
    Windows; the original is kept as grub.cfg.labfw-orig) so the first boot
    passes ds=nocloud; cloud-init then restores the stub (bootcmd) and
    writes /etc/cloud/cloud.cfg.d/99-labfw-nocloud.cfg (datasource_list:
    [ NoCloud, None ]) so later boots keep using the seed disk, which stays
    attached. The image's 90-hotplug-azure.yaml netplan file (DHCP on every
    hv_netvsc NIC) is removed, and the netplan IDs of the seed sort before it.

    The generated /etc/labfw/config.yaml: platform generic, policy.source arm,
    azure.auth from -Auth, network.interface eth0, internalInterfaces [eth1],
    dnatAddressMap {"*": "interface"}, dnsClients/managementSources = the LAN
    prefix, DNS proxy forced on, optional vpn section.

    Re-running is safe: the image is downloaded and converted once, a missing
    LAN switch is created, an existing VM is left alone unless -Replace.
    -WhatIf shows what would be done. -RenderOnly writes the seed files to a
    directory and touches nothing else (no Hyper-V needed; used by
    New-LabfwVM.Tests.ps1).

.EXAMPLE
    .\New-LabfwVM.ps1 -ReleaseTag v0.5.0 `
        -PolicyResourceId /subscriptions/<sub>/resourceGroups/rg-fw/providers/Microsoft.Network/firewallPolicies/fw-policy `
        -Auth clientCertificate -TenantId <tenant> -ClientId <appId> -CredentialFile .\azure-sp.pem -Location swedencentral

.EXAMPLE
    # Arc-enabled server: connect the VM with azcmagent after it booted.
    .\New-LabfwVM.ps1 -ReleaseTag v0.5.0 -PolicyResourceId <id> -Auth arc -LanSwitchType Private -VpnEnabled
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$')]
    [string] $Name = 'labfw',
    [ValidateRange(1, 64)]
    [int] $ProcessorCount = 1,
    [ValidateRange(536870912, 68719476736)]
    [long] $MemoryBytes = 1GB,
    [string] $WanSwitch = 'Default Switch',
    [string] $LanSwitch = 'labfw-lan',
    [ValidateSet('Internal', 'Private')]
    [string] $LanSwitchType = 'Internal',
    # labfw's LAN address and prefix length (gateway and DNS of the clients).
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$')]
    [string] $LanAddress = '192.168.250.1/24',
    # Optional address of the Hyper-V host on an Internal LAN switch, e.g. 192.168.250.2/24.
    [string] $LanHostAddress = '',

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^v\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$')]
    [string] $ReleaseTag,
    [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
    [string] $ReleaseRepo = 'onek8s/azure-lab-fw',
    [Parameter(Mandatory = $true)]
    [ValidatePattern('(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/firewallPolicies/[^/]+$')]
    [string] $PolicyResourceId,

    [ValidateSet('clientCertificate', 'clientSecret', 'arc', 'azureCLI')]
    [string] $Auth = 'clientCertificate',
    [string] $TenantId = '',
    [string] $ClientId = '',
    # PEM (certificate + private key) or PFX for clientCertificate; a file with the secret for clientSecret.
    [string] $CredentialFile = '',
    # Optional PFX password file.
    [string] $CertificatePasswordFile = '',
    # Azure region for service tags (azure.location); default: the policy's location.
    [ValidatePattern('^$|^[a-z][a-z0-9]{1,39}$')]
    [string] $Location = '',
    # Sources allowed to SSH to labfw (default: the LAN prefix).
    [string[]] $ManagementSources = @(),
    # Public key for the default 'ubuntu' user (optional; the console works without it).
    [string] $SshPublicKey = '',

    [switch] $VpnEnabled,
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$')]
    [string] $VpnAddress = '10.0.12.1/24',
    [ValidateRange(1, 65535)]
    [int] $VpnListenPort = 51820,
    # AllowedIPs of VPN client configs (default: the LAN prefix).
    [string[]] $VpnClientRoutes = @(),

    [string] $VMPath = '',
    [string] $ImageCacheDir = (Join-Path $env:ProgramData 'labfw\images'),
    [string] $ImageBaseUrl = 'https://cloud-images.ubuntu.com/releases/noble/release',
    [string] $ImageFile = 'ubuntu-24.04-server-cloudimg-amd64-azure.vhd.tar.gz',
    [switch] $VerifySignature,
    # Remove an existing VM of this name (and its disks) first.
    [switch] $Replace,
    [switch] $NoStart,
    # Write user-data, meta-data and network-config to this directory and exit.
    [string] $RenderOnly = '',
    # Testing aids for -RenderOnly: also write esp-grub.cfg, the first-boot
    # stub derived from this original EFI grub.cfg and root PARTUUID.
    [string] $RenderEspStubFrom = '',
    [string] $RootPartUuid = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoDeploy = Split-Path -Parent $PSScriptRoot           # deploy/
$cloudInitTemplate = Join-Path $repoDeploy 'cloud-init\cloud-init.yaml'
$installScript = Join-Path $repoDeploy 'cloud-init\install-labfw.sh'

# ---------------------------------------------------------------- helpers

function Get-PrefixInfo([string] $Cidr) {
    $ip, $len = $Cidr.Split('/')
    $bits = [int] $len
    if ($bits -lt 8 -or $bits -gt 30) { throw "prefix length of $Cidr must be 8..30" }
    $bytes = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
    [array]::Reverse($bytes)
    $addr = [System.BitConverter]::ToUInt32($bytes, 0)
    $mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $bits))
    $net = $addr -band $mask
    if ($addr -eq $net -or $addr -eq ($net -bor (-bnot $mask -band 0xFFFFFFFF))) {
        throw "$Cidr is the network or broadcast address"
    }
    $nb = [System.BitConverter]::GetBytes([uint32] $net)
    [array]::Reverse($nb)
    [pscustomobject]@{ Address = $ip; Bits = $bits; Prefix = ('{0}/{1}' -f ([System.Net.IPAddress]::new($nb)).ToString(), $bits) }
}

# Text for the Linux guest: LF line endings, no BOM.
function ConvertTo-Lf([string] $Text) { return ($Text -replace "`r`n", "`n") }

function ConvertTo-Base64([byte[]] $Bytes) { return [System.Convert]::ToBase64String($Bytes) }

function Write-LinuxFile([string] $Path, [string] $Text) {
    [System.IO.File]::WriteAllText($Path, (ConvertTo-Lf $Text), (New-Object System.Text.UTF8Encoding($false)))
}

# Hyper-V's MAC range 00:15:5D, derived from the VM name so re-renders agree.
function Get-StaticMac([string] $Seed) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Seed))
    return ('00155D{0:X2}{1:X2}{2:X2}' -f $h[0], $h[1], $h[2])
}

function Format-Mac([string] $Mac) {
    return (($Mac.ToLower() -split '(..)' | Where-Object { $_ }) -join ':')
}

# JSON is valid YAML; deploy/bicep renders the config the same way.
function Get-LabfwConfigJson {
    $lan = Get-PrefixInfo $LanAddress
    $azure = [ordered]@{ auth = $Auth }
    switch ($Auth) {
        'clientCertificate' {
            $azure.tenantId = $TenantId
            $azure.clientId = $ClientId
            $azure.certificateFile = $script:CredentialTarget
            if ($CertificatePasswordFile) { $azure.certificatePasswordFile = '/etc/labfw/credentials/azure-sp.pass' }
        }
        'clientSecret' {
            $azure.tenantId = $TenantId
            $azure.clientId = $ClientId
            $azure.clientSecretFile = $script:CredentialTarget
        }
    }
    if ($Location) { $azure.location = $Location }
    $mgmt = @($ManagementSources)
    if ($mgmt.Count -eq 0) { $mgmt = @($lan.Prefix) }
    $cfg = [ordered]@{
        platform  = 'generic'
        policy    = [ordered]@{ source = 'arm'; resourceId = $PolicyResourceId }
        azure     = $azure
        network   = [ordered]@{
            interface          = 'eth0'
            internalInterfaces = @('eth1')
            dnatAddressMap     = [ordered]@{ '*' = 'interface' }
            managementSources  = $mgmt
            dnsClients         = @($lan.Prefix)
        }
        dns       = [ordered]@{ forceEnable = $true }
        appProxy  = [ordered]@{ tls = [ordered]@{ generateLocalCA = $true } }
        dataplane = [ordered]@{ skipSysctl = $true }
    }
    if ($VpnEnabled) {
        $routes = @($VpnClientRoutes)
        if ($routes.Count -eq 0) { $routes = @($lan.Prefix) }
        $null = Get-PrefixInfo $VpnAddress
        $cfg.vpn = [ordered]@{
            enabled      = $true
            interface    = 'wg0'
            listenPort   = $VpnListenPort
            address      = $VpnAddress
            peersFile    = '/var/lib/labfw/vpn-peers.json'
            clientRoutes = $routes
        }
    }
    return ($cfg | ConvertTo-Json -Depth 10 -Compress)
}

function Get-LabfwUserData([string] $ConfigJson) {
    if (-not (Test-Path $cloudInitTemplate) -or -not (Test-Path $installScript)) {
        throw "run the script from a checkout of the repository (needs $cloudInitTemplate and $installScript)"
    }
    $tpl = ConvertTo-Lf ([System.IO.File]::ReadAllText($cloudInitTemplate))
    $sh = ConvertTo-Lf ([System.IO.File]::ReadAllText($installScript))
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $values = [ordered]@{
        '__CONFIG_YAML__'    = ConvertTo-Base64 $utf8.GetBytes($ConfigJson)
        '__INSTALL_SH__'     = ConvertTo-Base64 $utf8.GetBytes($sh)
        '__LABFW_VERSION__'  = $ReleaseTag
        '__ARCH__'           = 'amd64'
        '__RELEASE_REPO__'   = $ReleaseRepo
    }
    foreach ($k in $values.Keys) {
        if (-not $tpl.Contains($k)) { throw "cloud-init template lacks $k" }
        $tpl = $tpl.Replace($k, $values[$k])
    }
    if ($tpl -match '__[A-Z_]+__') { throw "unreplaced placeholder $($Matches[0]) in the cloud-init template" }

    # Extra write_files entries go right after "write_files:": credentials
    # (0600 root until install-labfw.sh hands them to labfw) and the
    # datasource override that keeps NoCloud after the first boot.
    $extra = New-Object System.Text.StringBuilder
    $files = @($script:CredentialFiles) + @([pscustomobject]@{ Target = '/etc/cloud/cloud.cfg.d/99-labfw-nocloud.cfg'; Mode = '0644'
            Bytes = $utf8.GetBytes("# New-LabfwVM.ps1: the Azure image allows only [ Azure ] (90_dpkg.cfg)`ndatasource_list: [ NoCloud, None ]`n") })
    foreach ($f in $files) {
        $mode = '0600'
        if ($f.PSObject.Properties['Mode']) { $mode = $f.Mode }
        [void] $extra.Append("  - path: $($f.Target)`n    encoding: b64`n    content: $(ConvertTo-Base64 $f.Bytes)`n    owner: root:root`n    permissions: `"$mode`"`n")
    }
    if ($extra.Length -gt 0) {
        $marker = "write_files:`n"
        $i = $tpl.IndexOf($marker)
        if ($i -lt 0) { throw 'cloud-init template has no write_files section' }
        $tpl = $tpl.Insert($i + $marker.Length, $extra.ToString())
    }
    $tpl += "`nhostname: $Name`n"
    # Every boot, early: put the original EFI GRUB stub back (first boot only
    # has a .labfw-orig) and drop the Azure image's hot-plug netplan file.
    $tpl += "bootcmd:`n" +
        "  - [sh, -c, 'f=/boot/efi/EFI/ubuntu/grub.cfg; if [ -f `"`$f.labfw-orig`" ]; then mv -f `"`$f.labfw-orig`" `"`$f`"; fi']`n" +
        "  - [rm, -f, /etc/netplan/90-hotplug-azure.yaml]`n"
    if ($SshPublicKey) {
        if ($SshPublicKey -notmatch '^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp\d+) [A-Za-z0-9+/=]+( [^\r\n]*)?$') { throw 'SshPublicKey is not an OpenSSH public key' }
        $tpl += "ssh_authorized_keys:`n  - $SshPublicKey`n"
    }
    return $tpl
}

function Get-LabfwNetworkConfig([string] $WanMac, [string] $LanMac) {
    $lan = Get-PrefixInfo $LanAddress
    # IDs sort before the image's 90-hotplug-azure.yaml "ephemeral" entry
    # (systemd-networkd uses the first matching .network file).
    return @"
version: 2
ethernets:
  00-labfw-wan:
    match:
      macaddress: "$(Format-Mac $WanMac)"
    set-name: eth0
    dhcp4: true
  00-labfw-lan:
    match:
      macaddress: "$(Format-Mac $LanMac)"
    set-name: eth1
    dhcp4: false
    addresses: [$($lan.Address)/$($lan.Bits)]

"@
}

function Get-LabfwMetaData {
    return "instance-id: $Name-$((Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'))`nlocal-hostname: $Name`n"
}

# First-boot EFI GRUB stub: the original search/prefix lines, then a boot
# entry with ds=nocloud (the only override of the image's datasource
# list), then the original configfile line as fallback if the boot fails.
function Get-EspGrubStub([string] $Original, [string] $RootUuid) {
    if ($RootUuid -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        throw "root partition UUID '$RootUuid' is not a GUID"
    }
    $lines = @((ConvertTo-Lf $Original).Split("`n") | Where-Object { $_.Trim() })
    $head = @($lines | Where-Object { $_ -notmatch '^\s*configfile\b' })
    $tail = @($lines | Where-Object { $_ -match '^\s*configfile\b' })
    if (-not ($head | Where-Object { $_ -match '^\s*search' }) -or $tail.Count -ne 1) {
        throw 'unexpected EFI grub.cfg (want search + prefix + configfile lines)'
    }
    $stub = @('# New-LabfwVM.ps1: first boot reads the cloud-init NoCloud seed (CIDATA disk).',
        '# cloud-init restores the original stub from grub.cfg.labfw-orig during that boot.') + $head + @(
        "linux /vmlinuz root=PARTUUID=$($RootUuid.ToLower()) ro console=tty1 console=ttyS0 ds=nocloud",
        'initrd /initrd.img',
        'boot') + $tail
    return (($stub -join "`n") + "`n")
}

function Write-CloudInitSeed([string] $Dir, [string] $UserData, [string] $MetaData, [string] $NetworkConfig) {
    Write-LinuxFile (Join-Path $Dir 'user-data') $UserData
    Write-LinuxFile (Join-Path $Dir 'meta-data') $MetaData
    Write-LinuxFile (Join-Path $Dir 'network-config') $NetworkConfig
}

# ---------------------------------------------------------------- inputs

$script:CredentialFiles = @()
$script:CredentialTarget = ''
switch ($Auth) {
    { $_ -in 'clientCertificate', 'clientSecret' } {
        $guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        if ($TenantId -notmatch $guid) { throw "-TenantId (GUID) is required with -Auth $Auth" }
        if ($ClientId -notmatch $guid) { throw "-ClientId (the application's client ID) is required with -Auth $Auth" }
        if (-not $CredentialFile -or -not (Test-Path -LiteralPath $CredentialFile -PathType Leaf)) {
            throw "-CredentialFile is required with -Auth $Auth (certificate PEM/PFX or secret file)"
        }
        $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $CredentialFile).ProviderPath)
        if ($Auth -eq 'clientCertificate') {
            $ext = if ([System.IO.Path]::GetExtension($CredentialFile) -match '^\.(pfx|p12)$') { 'pfx' } else { 'pem' }
            $script:CredentialTarget = "/etc/labfw/credentials/azure-sp.$ext"
        } else {
            $script:CredentialTarget = '/etc/labfw/credentials/azure-sp.secret'
        }
        $script:CredentialFiles += [pscustomobject]@{ Target = $script:CredentialTarget; Bytes = $bytes }
        if ($CertificatePasswordFile) {
            if ($Auth -ne 'clientCertificate') { throw '-CertificatePasswordFile needs -Auth clientCertificate' }
            $script:CredentialFiles += [pscustomobject]@{ Target = '/etc/labfw/credentials/azure-sp.pass'
                Bytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $CertificatePasswordFile).ProviderPath) }
        }
    }
    default {
        if ($CredentialFile -or $TenantId -or $ClientId) { throw "-CredentialFile/-TenantId/-ClientId are not used with -Auth $Auth" }
    }
}

$wanMac = Get-StaticMac "$Name/wan"
$lanMac = Get-StaticMac "$Name/lan"
$configJson = Get-LabfwConfigJson
$userData = Get-LabfwUserData $configJson
$metaData = Get-LabfwMetaData
$networkConfig = Get-LabfwNetworkConfig $wanMac $lanMac

if ($RenderOnly) {
    $null = New-Item -ItemType Directory -Force -Path $RenderOnly
    Write-CloudInitSeed -Dir $RenderOnly -UserData $userData -MetaData $metaData -NetworkConfig $networkConfig
    if ($RenderEspStubFrom) {
        Write-LinuxFile (Join-Path $RenderOnly 'esp-grub.cfg') (Get-EspGrubStub ([System.IO.File]::ReadAllText($RenderEspStubFrom)) $RootPartUuid)
    }
    Write-Output "seed files written to $RenderOnly (wan MAC $(Format-Mac $wanMac), lan MAC $(Format-Mac $lanMac))"
    return
}

# ---------------------------------------------------------------- Hyper-V

if (-not (Get-Module -ListAvailable -Name Hyper-V)) {
    throw 'the Hyper-V PowerShell module is required (Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All)'
}
Import-Module Hyper-V
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -and -not $WhatIfPreference) {
    throw 'run from an elevated PowerShell (Hyper-V and disk cmdlets need administrator rights)'
}

if (-not $VMPath) { $VMPath = Join-Path (Get-VMHost).VirtualMachinePath $Name }
$osDisk = Join-Path $VMPath "$Name-os.vhdx"
$seedDisk = Join-Path $VMPath "$Name-cidata.vhdx"

# --- base image: download, verify, extract, convert (cached) ---------------
function Get-BaseImage {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $base = Join-Path $ImageCacheDir ($ImageFile -replace '\.vhd\.tar\.gz$', '.vhdx')
    if (Test-Path $base) { Write-Verbose "base image cached: $base"; return $base }
    if (-not $PSCmdlet.ShouldProcess($base, "download $ImageBaseUrl/$ImageFile, verify SHA256SUMS, convert to VHDX")) { return $base }
    $null = New-Item -ItemType Directory -Force -Path $ImageCacheDir
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $tgz = Join-Path $ImageCacheDir $ImageFile
    $sums = Join-Path $ImageCacheDir 'SHA256SUMS'
    $ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is very slow with a progress bar on 5.1
    Invoke-WebRequest -UseBasicParsing -Uri "$ImageBaseUrl/SHA256SUMS" -OutFile $sums
    if ($VerifySignature) {
        $gpg = Get-Command gpg.exe -ErrorAction SilentlyContinue
        if (-not $gpg) { throw '-VerifySignature needs gpg.exe in PATH (e.g. from Git for Windows) with the Ubuntu cloud image signing key imported' }
        Invoke-WebRequest -UseBasicParsing -Uri "$ImageBaseUrl/SHA256SUMS.gpg" -OutFile "$sums.gpg"
        & $gpg.Source --verify "$sums.gpg" $sums
        if ($LASTEXITCODE -ne 0) { throw 'GPG signature of SHA256SUMS does not verify' }
    }
    $line = Get-Content $sums | Where-Object { $_ -match ('\s\*?' + [regex]::Escape($ImageFile) + '$') } | Select-Object -First 1
    if (-not $line) { throw "$ImageFile is not listed in SHA256SUMS" }
    $expected = ($line -split '\s+')[0].ToLower()
    if (-not (Test-Path $tgz) -or (Get-FileHash -Algorithm SHA256 $tgz).Hash.ToLower() -ne $expected) {
        Write-Host "downloading $ImageFile (~850 MB)"
        Invoke-WebRequest -UseBasicParsing -Uri "$ImageBaseUrl/$ImageFile" -OutFile $tgz
    }
    $actual = (Get-FileHash -Algorithm SHA256 $tgz).Hash.ToLower()
    if ($actual -ne $expected) { throw "SHA256 mismatch for ${ImageFile}: expected $expected, got $actual" }
    Write-Host "SHA256 verified ($actual)"
    $tar = Join-Path $env:SystemRoot 'System32\tar.exe'
    if (-not (Test-Path $tar)) { throw 'tar.exe not found (Windows 10 1803 or later ships it)' }
    $tmp = Join-Path $ImageCacheDir 'extract'
    $null = New-Item -ItemType Directory -Force -Path $tmp
    Write-Host 'extracting the VHD (needs ~31 GB free temporarily)'
    & $tar -xzf $tgz -C $tmp
    if ($LASTEXITCODE -ne 0) { throw 'tar.exe failed' }
    $vhd = Get-ChildItem -Path $tmp -Filter *.vhd | Select-Object -First 1
    if (-not $vhd) { throw "no .vhd inside $ImageFile" }
    Convert-VHD -Path $vhd.FullName -DestinationPath $base -VHDType Dynamic
    Remove-Item -Recurse -Force $tmp
    return $base
}

# --- NoCloud seed disk: FAT32 volume labelled CIDATA ------------------------
function New-SeedDisk {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    if (-not $PSCmdlet.ShouldProcess($seedDisk, 'create the cloud-init NoCloud seed disk (FAT32, label CIDATA)')) { return }
    if (Test-Path $seedDisk) { Remove-Item -Force $seedDisk }
    $null = New-VHD -Path $seedDisk -SizeBytes 64MB -Dynamic
    $mounted = $false
    try {
        $disk = Mount-VHD -Path $seedDisk -Passthru | Get-Disk
        $mounted = $true
        Initialize-Disk -Number $disk.Number -PartitionStyle MBR
        $part = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
        $null = Format-Volume -Partition $part -FileSystem FAT32 -NewFileSystemLabel 'CIDATA' -Confirm:$false
        $root = '{0}:\' -f (Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber).DriveLetter
        Write-CloudInitSeed -Dir $root -UserData $userData -MetaData $metaData -NetworkConfig $networkConfig
    } finally {
        if ($mounted) { Dismount-VHD -Path $seedDisk }
    }
}

# --- first boot with NoCloud: edit the EFI GRUB stub of the OS disk --------
function Set-FirstBootNoCloud {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    if (-not $PSCmdlet.ShouldProcess($osDisk, 'make the first boot use the NoCloud seed (EFI grub.cfg, ds=nocloud)')) { return }
    $espType = '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
    $linuxType = '{0fc63daf-8483-4772-8e79-3d69d8477de4}'
    $disk = Mount-VHD -Path $osDisk -NoDriveLetter -Passthru | Get-Disk
    $access = $null
    try {
        $parts = @(Get-Partition -DiskNumber $disk.Number)
        $esp = $parts | Where-Object { $_.GptType -eq $espType } | Select-Object -First 1
        # The root file system is the Linux partition with the lowest number
        # (partition 1 in Ubuntu cloud images; /boot is an XBOOTLDR partition).
        $root = $parts | Where-Object { $_.GptType -eq $linuxType } | Sort-Object PartitionNumber | Select-Object -First 1
        if (-not $esp -or -not $root) { throw "$osDisk has no EFI system or Linux root partition" }
        Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $esp.PartitionNumber -AssignDriveLetter
        $letter = (Get-Partition -DiskNumber $disk.Number -PartitionNumber $esp.PartitionNumber).DriveLetter
        if (-not $letter -or $letter -eq [char]0) { throw 'no drive letter for the EFI system partition' }
        $access = "${letter}:\"
        $cfg = Join-Path $access 'EFI\ubuntu\grub.cfg'
        $orig = "$cfg.labfw-orig"
        if (-not (Test-Path $orig)) { Copy-Item -Path $cfg -Destination $orig }
        $stub = Get-EspGrubStub ([System.IO.File]::ReadAllText($orig)) ($root.Guid.Trim('{}'))
        [System.IO.File]::WriteAllText($cfg, $stub, (New-Object System.Text.UTF8Encoding($false)))
    } finally {
        if ($access) { Remove-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $esp.PartitionNumber -AccessPath $access }
        Dismount-VHD -Path $osDisk
    }
}

# --- switches -------------------------------------------------------------------
if (-not (Get-VMSwitch -Name $WanSwitch -ErrorAction SilentlyContinue)) {
    throw "WAN switch '$WanSwitch' not found (Get-VMSwitch); use -WanSwitch with an External switch or the Default Switch"
}
if (-not (Get-VMSwitch -Name $LanSwitch -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess($LanSwitch, "create $LanSwitchType switch")) {
        $null = New-VMSwitch -Name $LanSwitch -SwitchType $LanSwitchType
    }
}
if ($LanHostAddress -and $LanSwitchType -eq 'Internal') {
    $h = Get-PrefixInfo $LanHostAddress
    $alias = "vEthernet ($LanSwitch)"
    if (-not (Get-NetIPAddress -InterfaceAlias $alias -IPAddress $h.Address -ErrorAction SilentlyContinue)) {
        if ($PSCmdlet.ShouldProcess($alias, "assign $LanHostAddress")) {
            $null = New-NetIPAddress -InterfaceAlias $alias -IPAddress $h.Address -PrefixLength $h.Bits
        }
    }
}

# --- VM ---------------------------------------------------------------------------
$existing = Get-VM -Name $Name -ErrorAction SilentlyContinue
if ($existing) {
    if (-not $Replace) {
        Write-Warning "VM '$Name' exists; nothing changed (use -Replace to recreate it)"
        return
    }
    if ($PSCmdlet.ShouldProcess($Name, 'remove the existing VM and its disks')) {
        Stop-VM -Name $Name -TurnOff -Force -ErrorAction SilentlyContinue
        Remove-VM -Name $Name -Force
        foreach ($d in $osDisk, $seedDisk) { if (Test-Path $d) { Remove-Item -Force $d } }
    }
}

$baseImage = Get-BaseImage
if ($PSCmdlet.ShouldProcess($osDisk, "copy $baseImage")) {
    $null = New-Item -ItemType Directory -Force -Path $VMPath
    Copy-Item -Path $baseImage -Destination $osDisk
}
Set-FirstBootNoCloud
New-SeedDisk

if ($PSCmdlet.ShouldProcess($Name, "create Generation 2 VM ($ProcessorCount vCPU, $($MemoryBytes / 1MB) MiB, WAN '$WanSwitch', LAN '$LanSwitch')")) {
    $null = New-VM -Name $Name -Generation 2 -MemoryStartupBytes $MemoryBytes -VHDPath $osDisk -SwitchName $WanSwitch -Path (Split-Path -Parent $VMPath)
    Set-VM -Name $Name -ProcessorCount $ProcessorCount -StaticMemory -AutomaticStopAction ShutDown
    try { Set-VM -Name $Name -AutomaticCheckpointsEnabled $false } catch { Write-Verbose 'automatic checkpoints not supported on this host' }
    Set-VMFirmware -VMName $Name -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
    Get-VMNetworkAdapter -VMName $Name | Rename-VMNetworkAdapter -NewName 'wan'
    Set-VMNetworkAdapter -VMName $Name -Name 'wan' -StaticMacAddress $wanMac
    Add-VMNetworkAdapter -VMName $Name -Name 'lan' -SwitchName $LanSwitch -StaticMacAddress $lanMac
    Add-VMHardDiskDrive -VMName $Name -Path $seedDisk
    Set-VMFirmware -VMName $Name -FirstBootDevice (Get-VMHardDiskDrive -VMName $Name | Where-Object { $_.Path -eq $osDisk })
    if (-not $NoStart) { Start-VM -Name $Name }
}

$lanInfo = Get-PrefixInfo $LanAddress
Write-Host @"

labfw VM '$Name' $(if ($NoStart) { 'created' } else { 'started' }). First boot installs labfw $ReleaseTag (a few minutes).
  LAN clients on switch '$LanSwitch': address in $($lanInfo.Prefix), gateway and DNS $($lanInfo.Address)
  WAN: DHCP on '$WanSwitch' (Get-VMNetworkAdapter -VMName $Name -Name wan).IPAddresses
  Check: vmconnect localhost $Name, then 'sudo systemctl status labfw', 'labfw fetch --config /etc/labfw/config.yaml --out /tmp/p.json',
         'curl -s 127.0.0.1:9090/status'
"@
if ($Auth -eq 'arc') {
    Write-Host '  Azure Arc: connect the VM with azcmagent (https://aka.ms/azcmagent), then run deploy/scripts/hybrid-identity.sh --arc-machine <id> and sudo systemctl restart labfw'
}
