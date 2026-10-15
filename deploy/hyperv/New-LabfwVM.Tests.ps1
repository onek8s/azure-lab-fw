#Requires -Version 5.1
<#
.SYNOPSIS
    Offline test of New-LabfwVM.ps1's rendering (-RenderOnly): no Hyper-V,
    no network. Runs on Windows PowerShell 5.1 and PowerShell 7 (CI: pwsh on
    Linux).

      pwsh -File deploy/hyperv/New-LabfwVM.Tests.ps1

    With $env:LABFW_BIN pointing at a labfw binary, the generated config is
    also loaded by labfw itself (`labfw compile --config ... --policy ...`);
    with python3 + PyYAML, user-data and network-config are parsed as YAML.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script = Join-Path $PSScriptRoot 'New-LabfwVM.ps1'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$installSh = Join-Path $repo 'deploy/cloud-init/install-labfw.sh'
$fixture = Join-Path $repo 'test/fixtures/policies/two-armed/policy.json'
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('labfw-hyperv-test-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $tmp
$failures = 0

function Pass([string] $m) { Write-Host "PASS $m" }
function Fail([string] $m) { Write-Host "FAIL $m"; $script:failures++ }
function Check([bool] $cond, [string] $m) { if ($cond) { Pass $m } else { Fail $m } }

$policyId = '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-fw/providers/Microsoft.Network/firewallPolicies/fw-policy'
$tenant = '11111111-2222-3333-4444-555555555555'
$app = '66666666-7777-8888-9999-000000000000'
$pemText = "-----BEGIN PRIVATE KEY-----`nMIIfake`n-----END PRIVATE KEY-----`n"
$pem = Join-Path $tmp 'sp.pem'
[System.IO.File]::WriteAllText($pem, $pemText)
$secret = Join-Path $tmp 'sp.secret'
[System.IO.File]::WriteAllText($secret, "s3cr3t`n")
$origStub = Join-Path $tmp 'orig-grub.cfg'
[System.IO.File]::WriteAllText($origStub, "search.fs_uuid 0f084f18-3e6e-4e6e-94e9-4b9dc94592b6 root `nset prefix=(`$root)'/grub'`nconfigfile `$prefix/grub.cfg`n")

function Invoke-Render([string] $Dir, [hashtable] $Extra) {
    $p = @{ ReleaseTag = 'v1.2.3'; PolicyResourceId = $policyId; RenderOnly = $Dir; ImageCacheDir = (Join-Path $tmp 'cache') }
    foreach ($k in $Extra.Keys) { $p[$k] = $Extra[$k] }
    & $script @p | Out-Null
}

function Get-B64Entry([string] $UserData, [string] $Path) {
    $m = [regex]::Match($UserData, '(?m)^  - path: ' + [regex]::Escape($Path) + '\n    encoding: b64\n    content: (\S+)\n    owner: (\S+)\n    permissions: "(\d+)"')
    if (-not $m.Success) { return $null }
    return [pscustomobject]@{ Bytes = [System.Convert]::FromBase64String($m.Groups[1].Value); Owner = $m.Groups[2].Value; Mode = $m.Groups[3].Value }
}

function Test-LinuxText([string] $Path) {
    $b = [System.IO.File]::ReadAllBytes($Path)
    $bom = $b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF
    return (-not $bom) -and (-not ([System.Text.Encoding]::UTF8.GetString($b).Contains("`r")))
}

try {
    # --- 1. certificate + VPN -----------------------------------------------
    $d1 = Join-Path $tmp 'cert'
    Invoke-Render $d1 @{ TenantId = $tenant; ClientId = $app; CredentialFile = $pem; Location = 'swedencentral'; VpnEnabled = $true
        SshPublicKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTests user@host'; RenderEspStubFrom = $origStub
        RootPartUuid = '5D35ED95-4B89-4B10-AABF-C3D4C3121839' }
    foreach ($f in 'user-data', 'meta-data', 'network-config', 'esp-grub.cfg') {
        Check (Test-LinuxText (Join-Path $d1 $f)) "${f}: LF line endings, no BOM"
    }
    $ud = [System.IO.File]::ReadAllText((Join-Path $d1 'user-data'))
    Check ($ud.StartsWith("#cloud-config`n")) 'user-data starts with #cloud-config'
    Check (-not ($ud -match '__[A-Z_]+__')) 'no unreplaced placeholders'
    Check ($ud.Contains('  - [/usr/local/sbin/install-labfw.sh, "v1.2.3", "amd64", "onek8s/azure-lab-fw"]')) 'runcmd: same 3-argument call as main.bicep'
    $sh = Get-B64Entry $ud '/usr/local/sbin/install-labfw.sh'
    $want = [System.IO.File]::ReadAllText($installSh) -replace "`r`n", "`n"
    Check ($null -ne $sh -and [System.Text.Encoding]::UTF8.GetString($sh.Bytes) -eq $want -and $sh.Mode -eq '0755') 'install-labfw.sh embedded unchanged (LF)'
    $cred = Get-B64Entry $ud '/etc/labfw/credentials/azure-sp.pem'
    Check ($null -ne $cred -and [System.Text.Encoding]::UTF8.GetString($cred.Bytes) -eq $pemText -and $cred.Mode -eq '0600' -and $cred.Owner -eq 'root:root') 'certificate in write_files, 0600'
    $ds = Get-B64Entry $ud '/etc/cloud/cloud.cfg.d/99-labfw-nocloud.cfg'
    Check ($null -ne $ds -and [System.Text.Encoding]::UTF8.GetString($ds.Bytes).Contains('datasource_list: [ NoCloud, None ]')) 'NoCloud datasource kept after the first boot'
    Check ($ud.Contains("bootcmd:`n  - [sh, -c, 'f=/boot/efi/EFI/ubuntu/grub.cfg; if [ -f `"`$f.labfw-orig`" ]; then mv -f `"`$f.labfw-orig`" `"`$f`"; fi']`n  - [rm, -f, /etc/netplan/90-hotplug-azure.yaml]")) 'bootcmd restores the GRUB stub, drops the hot-plug netplan file'
    Check ($ud.Contains("ssh_authorized_keys:`n  - ssh-ed25519 ")) 'ssh key'
    $cfgEntry = Get-B64Entry $ud '/etc/labfw/config.yaml'
    $cfgText = [System.Text.Encoding]::UTF8.GetString($cfgEntry.Bytes)
    $cfg = $cfgText | ConvertFrom-Json
    Check ($cfg.platform -eq 'generic' -and $cfg.policy.source -eq 'arm' -and $cfg.policy.resourceId -eq $policyId) 'config: platform generic, ARM source'
    Check ($cfg.azure.auth -eq 'clientCertificate' -and $cfg.azure.tenantId -eq $tenant -and $cfg.azure.clientId -eq $app -and
        $cfg.azure.certificateFile -eq '/etc/labfw/credentials/azure-sp.pem' -and $cfg.azure.location -eq 'swedencentral') 'config: azure section'
    Check ($cfg.network.interface -eq 'eth0' -and (@($cfg.network.internalInterfaces) -join ',') -eq 'eth1' -and
        $cfg.network.dnatAddressMap.'*' -eq 'interface' -and (@($cfg.network.dnsClients) -join ',') -eq '192.168.250.0/24' -and
        (@($cfg.network.managementSources) -join ',') -eq '192.168.250.0/24') 'config: two-armed network'
    Check ($cfg.dns.forceEnable -eq $true -and $cfg.dataplane.skipSysctl -eq $true) 'config: DNS proxy forced, sysctls from the package'
    Check ($cfg.vpn.enabled -eq $true -and $cfg.vpn.address -eq '10.0.12.1/24' -and $cfg.vpn.listenPort -eq 51820 -and
        (@($cfg.vpn.clientRoutes) -join ',') -eq '192.168.250.0/24') 'config: vpn section'
    $nc = [System.IO.File]::ReadAllText((Join-Path $d1 'network-config'))
    Check ($nc -match '00-labfw-wan:\n    match:\n      macaddress: "00:15:5d(:[0-9a-f]{2}){3}"\n    set-name: eth0\n    dhcp4: true') 'network-config: WAN DHCP by MAC'
    Check ($nc -match '00-labfw-lan:\n    match:\n      macaddress: "00:15:5d(:[0-9a-f]{2}){3}"\n    set-name: eth1\n    dhcp4: false\n    addresses: \[192\.168\.250\.1/24\]') 'network-config: LAN static by MAC'
    $md = [System.IO.File]::ReadAllText((Join-Path $d1 'meta-data'))
    Check ($md -match '^instance-id: labfw-\d{14}\nlocal-hostname: labfw\n$') 'meta-data'
    $stub = [System.IO.File]::ReadAllText((Join-Path $d1 'esp-grub.cfg'))
    Check ($stub.Contains("search.fs_uuid 0f084f18-3e6e-4e6e-94e9-4b9dc94592b6 root `nset prefix=(`$root)'/grub'`nlinux /vmlinuz root=PARTUUID=5d35ed95-4b89-4b10-aabf-c3d4c3121839 ro console=tty1 console=ttyS0 ds=nocloud`ninitrd /initrd.img`nboot`nconfigfile `$prefix/grub.cfg`n")) 'EFI GRUB stub: first boot with ds=nocloud, original as fallback'

    # Deterministic MACs per VM name.
    $d1b = Join-Path $tmp 'cert-again'
    Invoke-Render $d1b @{ TenantId = $tenant; ClientId = $app; CredentialFile = $pem }
    Check ([System.IO.File]::ReadAllText((Join-Path $d1b 'network-config')) -eq $nc) 'MACs stable across renders'

    # --- 2. client secret, custom LAN ---------------------------------------
    $d2 = Join-Path $tmp 'secret'
    Invoke-Render $d2 @{ Auth = 'clientSecret'; TenantId = $tenant; ClientId = $app; CredentialFile = $secret; LanAddress = '10.77.0.254/16'; Name = 'fw2' }
    $ud2 = [System.IO.File]::ReadAllText((Join-Path $d2 'user-data'))
    $cfg2 = [System.Text.Encoding]::UTF8.GetString((Get-B64Entry $ud2 '/etc/labfw/config.yaml').Bytes) | ConvertFrom-Json
    Check ($cfg2.azure.auth -eq 'clientSecret' -and $cfg2.azure.clientSecretFile -eq '/etc/labfw/credentials/azure-sp.secret' -and
        -not ($cfg2.azure.PSObject.Properties.Name -contains 'clientSecret')) 'clientSecret: file only, never inline'
    Check ((@($cfg2.network.dnsClients) -join ',') -eq '10.77.0.0/16' -and -not ($cfg2.PSObject.Properties.Name -contains 'vpn')) 'custom LAN prefix, no vpn section'
    Check ((Get-B64Entry $ud2 '/etc/labfw/credentials/azure-sp.secret').Mode -eq '0600') 'secret in write_files, 0600'
    Check ([System.IO.File]::ReadAllText((Join-Path $d2 'network-config')).Contains('addresses: [10.77.0.254/16]')) 'custom LAN address'

    # --- 3. Arc ---------------------------------------------------------------
    $d3 = Join-Path $tmp 'arc'
    Invoke-Render $d3 @{ Auth = 'arc' }
    $ud3 = [System.IO.File]::ReadAllText((Join-Path $d3 'user-data'))
    $cfg3 = [System.Text.Encoding]::UTF8.GetString((Get-B64Entry $ud3 '/etc/labfw/config.yaml').Bytes) | ConvertFrom-Json
    Check ($cfg3.azure.auth -eq 'arc' -and @($cfg3.azure.PSObject.Properties).Count -eq 1 -and -not $ud3.Contains('/etc/labfw/credentials/')) 'arc: no credentials'

    # --- 4. invalid input -------------------------------------------------------
    $bad = @(
        @{ Name = 'cert without tenant'; P = @{ ClientId = $app; CredentialFile = $pem } },
        @{ Name = 'cert without file'; P = @{ TenantId = $tenant; ClientId = $app } },
        @{ Name = 'arc with credential'; P = @{ Auth = 'arc'; CredentialFile = $pem } },
        @{ Name = 'LAN network address'; P = @{ Auth = 'arc'; LanAddress = '192.168.250.0/24' } },
        @{ Name = 'LAN /31'; P = @{ Auth = 'arc'; LanAddress = '192.168.250.1/31' } },
        @{ Name = 'bad ssh key'; P = @{ Auth = 'arc'; SshPublicKey = 'not a key' } }
    )
    foreach ($b in $bad) {
        $threw = $false
        try { Invoke-Render (Join-Path $tmp 'bad') $b.P } catch { $threw = $true }
        Check $threw "rejected: $($b.Name)"
    }
    foreach ($b in @(@{ Name = 'bad tag'; P = @{ ReleaseTag = 'latest' } }, @{ Name = 'bad policy id'; P = @{ PolicyResourceId = '/subscriptions/x/foo' } })) {
        $threw = $false
        $p = @{ ReleaseTag = 'v1.2.3'; PolicyResourceId = $policyId; RenderOnly = (Join-Path $tmp 'bad'); Auth = 'arc' }
        foreach ($k in $b.P.Keys) { $p[$k] = $b.P[$k] }
        try { & $script @p | Out-Null } catch { $threw = $true }
        Check $threw "rejected: $($b.Name)"
    }

    # --- 5. optional: labfw parses the config; YAML parses ----------------------
    if ($env:LABFW_BIN -and (Test-Path $env:LABFW_BIN)) {
        foreach ($c in @(@{ N = 'cert'; T = $cfgText }, @{ N = 'secret'; T = ($cfg2 | ConvertTo-Json -Depth 10) }, @{ N = 'arc'; T = ($cfg3 | ConvertTo-Json -Depth 10) })) {
            $cf = Join-Path $tmp "config-$($c.N).yaml"
            [System.IO.File]::WriteAllText($cf, $c.T)
            $out = & $env:LABFW_BIN compile --config $cf --policy $fixture --format diagnostics 2>&1
            Check ($LASTEXITCODE -eq 0) "labfw accepts the $($c.N) config ($(($out | Out-String).Trim()))"
        }
    } else {
        Write-Host 'SKIP labfw config check (set LABFW_BIN)'
    }
    $py = Get-Command python3 -ErrorAction SilentlyContinue
    if ($py) {
        & $py.Source -c 'import yaml' 2>$null
        if ($LASTEXITCODE -eq 0) {
            & $py.Source -I -c 'import sys, yaml; u = yaml.safe_load(open(sys.argv[1])); n = yaml.safe_load(open(sys.argv[2])); assert u["runcmd"] and u["bootcmd"] and len(u["write_files"]) == 4, u.keys(); assert set(n["ethernets"]) == {"00-labfw-wan", "00-labfw-lan"}' (Join-Path $d1 'user-data') (Join-Path $d1 'network-config')
            Check ($LASTEXITCODE -eq 0) 'user-data and network-config are valid YAML'
        } else { Write-Host 'SKIP YAML parse (no PyYAML)' }
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

if ($failures -gt 0) { Write-Host "New-LabfwVM.Tests: $failures failure(s)"; exit 1 }
Write-Host 'New-LabfwVM.Tests: all passed'
