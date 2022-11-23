using namespace System.Security.Cryptography.X509Certificates
using namespace System.Management.Automation

$importModule = Get-Command -Name Import-Module -Module Microsoft.PowerShell.Core
if ('PSWSMan.OnModuleImportAndRemove' -as [type]) {
    &$importModule -Force -Assembly ([PSWSMan.OnModuleImportAndRemove].Assembly)
}
else {
    &$importModule ([IO.Path]::Combine($PSScriptRoot, 'bin', 'PSWSMan.dll')) -ErrorAction Stop
}

$Script:LibPath = Join-Path -Path $PSScriptRoot -ChildPath bin

class X509CertificateChainAttribute : ArgumentTransformationAttribute {
    [object] Transform([EngineIntrinsics]$EngineIntrinsics, [object]$InputData) {
        # X509Certificate2Collection is an IEnumerable so we cannot use it in a switch statement or else an empty
        # collection becomes $null which we don't want.
        if ($InputData -is [X509Certificate2Collection]) {
            return $InputData
        }

        $outputData = switch($InputData) {
             { ($_ -is [X509Certificate2]) } { [X509Certificate2Collection]::new($_) }
             default {
                 throw [ArgumentTransformationMetadataException]::new(
                     "Could not convert input '$_' to a valid X509Certificate2Collection object."
                 )
             }
        }
        return $outputData
    }
}

Function pswsman_exec {
    <#
    .SYNOPSIS
    Wraps a native exec call and output as separate streams for manual handling
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [String]
        $FilePath,

        [Parameter(Position=1, ValueFromRemainingArguments=$true)]
        [String[]]
        $Arguments
    )

    [PSWSMan.Process]::Exec($FIlePath, $Arguments)
}

Function Get-OpenSSLInfo {
    <#
    .SYNOPSIS
    Gets the OpenSSL version and SSL dir that is currently installed.
    #>
    [CmdletBinding()]
    param (
        [String[]]
        $LibSSL
    )

    $sslPaths = if ($LibSSL) {
        $LibSSL
    }
    elseif ($IsMacOS) {
        @(
            'libssl',
            'libssl.dylib',
            'libssl.1.1.dylib',
            'libssl.10.dylib',
            'libssl.1.0.0.dylib',
            'libssl.3.dylib'
        )
    }
    else {
        @(
            'libssl',
            'libssl.so',
            'libssl.so.1.1',
            'libssl.so.10',
            'libssl.so.1.0.0',
            'libssl.so.3'
        )
    }
    Write-Verbose -Message "Getting OpenSSL version for '$($sslPaths -join "', '")'"

    $versionNum = [PSWSMan.Native]::OpenSSL_version_num($sslPaths)

    # MNNFFPPS: major minor fix patch status
    # For major=1 patch refers to the letter as a number, e.g. 1 == 'a', 2 == 'b', etc
    # We don't care about status
    $major = ($versionNum -band 0xF0000000) -shr 28
    $minor = ($versionNum -band 0x0FF00000) -shr 20
    $fix = ($versionNum -band 0x000FF000) -shr 12
    $patch = ($versionNum -band 0x00000FF0) -shr 4

    $version = [Version]::new($major, $minor, $fix, $patch)

    $sslDir = [PSWSMan.Native]::OpenSSL_version($sslPaths, 4)  # OPENSSL_DIR
    $sslDir = if ($sslDir) {
        $sslDir |
            Select-String -Pattern 'OPENSSLDIR:\s+[\"|''](.*)[\"|'']$' |
            ForEach-Object -Process { $_.Matches[0].Groups[1].Value } |
            Select-Object -First 1
    }

    [PSCustomObject]@{
        Version = $version
        SSLDir = $sslDir
    }
}

Function Test-MacOSArchitecture {
    <#
    .SYNOPSIS
    Validates the binary specified is valid with the architecture desired.
    #>
    [CmdletBinding()]
    param (
        [String]
        $DesiredArch,

        [String]
        $Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Verbose -Message "Binary at '$Path' does not exist - cannot test architecture"
        $false
        return
    }

    $archs = (lipo -archs $Path) -split " "
    Write-Verbose -Message "Checking if '$DesiredArch' for '$Path' is one of '$($archs -join "', '")'"
    $DesiredArch -in $archs
}

Function Get-MacOSOpenSSL {
    <#
    .SYNOPSIS
    Gets the libcrypto and libssl paths to use on macOS. It gets the path from the brew install openssl package and
    falls back to the port install package. We cannot use the LibreSSL version distributed by Apple as that is old
    and isn't compatible with libmi.
    #>
    [CmdletBinding()]
    param ()

    $desiredArch = uname -m
    $portLocations = @('port', '/opt/local/bin/port')
    $brewLocations = @('brew', ($desiredArch -eq 'x86_64' ? '/usr/local/bin/brew' : '/opt/homebrew/bin/brew'))

    # Try a few locations just in case it's not in the PATH or the wrong architecture it
    foreach ($brewPath in $brewLocations) {
        $app = Get-Command -Name $brewPath -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $app) {
            Write-Verbose -Message "Failed to find brew at '$brewPath'"
            continue
        }

        $brewPath = $app.Path

        # OpenSSL can be installed under a few different names
        foreach ($package in @('openssl', 'openssl@3', 'openssl@1.1')) {
            $brewInfo = pswsman_exec $brewPath --prefix $package
            $msg = "Attempting to get OpenSSL info with $brewPath --prefix $package`nSTDOUT: {0}`nSTDERR: {1}`nRC: {2}" -f (
                $brewInfo.Stdout, $brewInfo.Stderr, $brewInfo.ExitCode)
            Write-Verbose -Message $msg

            if ($brewInfo.ExitCode -ne 0) {
                continue
            }

            $brewLibCrypto = Join-Path -Path $brewInfo.Stdout.Trim() lib libcrypto.dylib
            $brewLibSSL = Join-Path -Path $brewInfo.Stdout.Trim() lib libssl.dylib
            Write-Verbose -Message "Checking arch information for '$brewLibCrypto' and '$brewLibSSL'"
            if (
                (Test-MacOSArchitecture -DesiredArch $desiredArch -Path $brewLibCrypto) -and
                (Test-MacOSArchitecture -DesiredArch $desiredArch -Path $brewLibSSL)
            ) {
                Write-Verbose "Brew $package libcrypto|ssl exists and is valid at '$brewLibCrypto' and '$brewLibSSL'"
                [PSCustomObject]@{
                    LibCrypto = $brewLibCrypto
                    LibSSL = $brewLibSSL
                }
                return
            }
        }
    }

    Write-Verbose -Message "Failed to find OpenSSL with homebrew, falling back to port"

    foreach ($portPath in $portLocations) {
        $app = Get-Command -Name $portPath -Commandtype Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $app) {
            Write-Verbose -Message "Failed to find port at '$portPath'"
            continue
        }

        $portPath = $app.Path

        foreach ($package in @('openssl', 'openssl3', 'openssl11')) {
            $portInfo = pswsman_exec $portPath contents $package
            $msg = "Attempting to get OpenSSL info $portPath contents $package`nSTDERR: {0}`nRC: {1}" -f (
                $portInfo.Stderr, $portInfo.ExitCode)
            Write-Verbose -Message $msg

            if ($portInfo.ExitCode -ne 0) {
                continue
            }

            $portLibCrypto = $portLibSSL = $null
            $portInfo.Stdout -split '\r?\n' | ForEach-Object -Process {
                $line = $_.Trim()
                if (-not $line.StartsWith('/') -or ($portLibCrypto -and $portLibSSL)) {
                    return
                }

                if ($line -like '*/libcrypto.dylib') {
                    $portLibCrypto = $line
                }
                elseif ($line -like '*/libssl.dylib') {
                    $portLibSSL = $line
                }
            }

            if (-not ($portLibCrypto -and $portLibSSL)) {
                Write-Verbose -Message "Failed to find libs for port $package"
                continue
            }

            Write-Verbose -Message "Checking arch information for '$portLibCrypto' and '$portLibSSL'"
            if (
                (Test-MacOSArchitecture -DesiredArch $desiredArch -Path $portLibCrypto) -and
                (Test-MacOSArchitecture -DesiredArch $desiredArch -Path $portLibSSL)
            ) {
                Write-Verbose "Port $package libcrypto|ssl exists and is valid at '$portLibCrypto' and $portLibSSL'"
                [PSCustomObject]@{
                    LibCrypto = $portLibCrypto
                    LibSSL = $portLibSSL
                }
                return
            }
        }
    }
}

Function Get-HostInfo {
    <#
    .SYNOPSIS
    Gets the host info that selects the native libraries to install.

    .NOTES
    Currently we support the following C Standard Libraries:
        macOS
        glibc
        musl

    Each support OpenSSL 1.1.x and 3.x and glibc also supports 1.0.x.
    #>
    [CmdletBinding()]
    param ()

    $info = if ($IsMacOS) {
        $libDetails = Get-MacOSOpenSSL

        if ($libDetails) {
            $opensslVersion = (Get-OpenSSLInfo -LibSSL $libDetails.LibSSL).Version
            Write-Verbose -Message ("OpenSSL Version: Major {0} Minor {1} Patch {2}" -f (
                $opensslVersion.Major, $opensslVersion.Minor, $opensslVersion.Build))

            $openssl, $cryptoSource, $sslSource = switch ($opensslVersion) {
                { $_.Major -eq 1 -and $_.Minor -eq 1 } { '1.1', 'libcrypto.1.1.dylib', 'libssl.1.1.dylib' }
                { $_.Major -eq 3 } { '3', 'libcrypto.3.dylib', 'libssl.3.dylib' }
                # Just default to 1.1 in case something catastrophic went wrong
                default { '1.1', 'libcrypto.1.1.dylib', 'libssl.1.1.dylib' }
            }

            [PSCustomObject]@{
                Distribution = 'macOS'
                StandardLib = 'macOS'
                OpenSSL = $openssl
                LibCrypto = @{
                    Source = $cryptoSource
                    Target = $libDetails.LibCrypto
                }
                LibSSL = @{
                    Source = $sslSource
                    Target = $libDetails.LibSSL
                }
            }
        }
    }
    else {
        $opensslVersion = (Get-OpenSSLInfo).Version
        Write-Verbose -Message ("OpenSSL Version: Major {0} Minor {1} Patch {2}" -f (
            $opensslVersion.Major, $opensslVersion.Minor, $opensslVersion.Build))

        $openssl = switch ($opensslVersion) {
            { $_.Major -eq 1 -and $_.Minor -eq 0 } { '1.0' }
            { $_.Major -eq 1 -and $_.Minor -eq 1 } { '1.1' }
            { $_.Major -eq 3 } { '3' }
        }

        $cStd = $null
        try {
            [void][PSWSMan.Native]::gnu_get_libc_version()
            $cStd = 'glibc'
        }
        catch [EntryPointNotFoundException] {
            # gnu_get_libc_version() is GLIBC, we fallback on a check to musl through ldd --version.
            $libcInfo = pswsman_exec ldd --version
            $libcVerbose = "Not glibc, checking musl with ldd --version:`nSTDOUT: {0}`nSTDERR: {1}`nRC: {2}" -f (
                $libcInfo.Stdout, $libcInfo.Stderr, $libcInfo.ExitCode)
            Write-Verbose -Message $libcVerbose

            # ldd --version can output on either STDOUT/STDERR so we check both
            if (($libcInfo.Stdout + $libcInfo.Stderr).Contains('musl', 'CurrentCultureIgnoreCase')) {
                $cStd = 'musl'
            }
        }

        # We don't need to modify the symlinks as the linked SSL libs should already match what's in the PATH.
        # Only exception is CentOS 7 which has libcrypto.so.10 and libssl.so.10.
        # | OpenSSL Version |     crypto name    |     ssl name    |
        # | 1.0.x           | libcrypto.so.1.0.0 | libssl.so.1.0.0 |
        # | 1.1.x           | libcrypto.so.1.1   | libssl.so.1.1   |
        # | 3.x             | libcrypto.so.3     | libssl.so.3     |
        $distro = Get-DistributionInfo
        if ($distro.Name -eq 'centos' -and $distro.Info.VERSION_ID -eq '7') {
            $libCrypto = @{
                Source = 'libcrypto.so.1.0.0'
                Target = '/lib64/libcrypto.so.10'
            }
            $libSSL = @{
                Source = 'libssl.so.1.0.0'
                Target = '/lib64/libssl.so.10'
            }
        }
        else {
            $libCrypto = $null
            $libSSL = $null
        }

        [PSCustomObject]@{
            StandardLib = $cStd
            OpenSSL = $openssl
            LibCrypto = $libCrypto
            LibSSL = $libSSL
        }
    }

    Write-Verbose -Message "Host Info:`n$($info | ConvertTo-Json)"
    $info
}

Function Get-DistributionInfo {
    <#
    .SYNOPSIS
    Gets the host distribution name as understood by PSWSMan.
    #>
    [CmdletBinding()]
    param ()

    $info = [Ordered]@{
        Platform = $PSVersionTable.Platform
        OS = $PSVersionTable.OS
        Name = ''
        Info = [Ordered]@{}
    }

    if (Test-Path -LiteralPath /etc/os-release -PathType Leaf) {
        Get-Content -LiteralPath /etc/os-release | ForEach-Object -Process {
            if (-not $_.Trim() -or -not $_.Contains('=')) {
                return
            }

            $key, $value = $_.Split('=', 2)
            if ($value.StartsWith('"')) {
                $value = $value.Substring(1)
            }
            if ($value.EndsWith('"')) {
                $value = $value.Substring(0, $value.Length - 1)
            }
            $info.Info.$key = $value
        }

        foreach ($key in @('ID', 'NAME')) {
            if ($info.Info.Contains($key) -and $info.Info.$key) {
                $info.Name = $info.Info.$key
                break
            }
        }
    }

    [PSCustomObject]$info
}

Function Install-WSMan {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [String]
        $Distribution
    )

    if ($Distribution) {
        Write-Warning -Message "-Distribution is deprecated and will be removed in a future version"
    }

    $hostInfo = Get-HostInfo

    if (-not $hostInfo.StandardLib -or -not $hostInfo.OpenSSL) {
        $msg = "Failed to select the necessary library, the host isn't macOS, Linux based on GLIBC or musl, or OpenSSL isn't installed"
        Write-Error -Message $msg -Category InvalidOperation
        return
    }

    $library = '{0}-{1}' -f ($hostInfo.StandardLib, $hostInfo.OpenSSL)
    Write-Verbose -Message "Installing WSMan libs for '$library'"

    $pwshDir = Split-Path -Path ([PSObject].Assembly.Location) -Parent
    $distributionLib = Join-Path $Script:LibPath -ChildPath $library
    $libExtension = if ($hostInfo.StandardLib -eq 'macOS') { 'dylib' } else { 'so' }

    $notify = $false
    Get-ChildItem -LiteralPath $distributionLib -File -Filter "*.$libExtension" | ForEach-Object -Process {
        Write-Verbose -Message "Checking to see if $($_.Name) is installed"
        $destPath = Join-Path -Path $pwshDir -ChildPath $_.Name

        $change = $true
        if (Test-Path -LiteralPath $destPath) {
            $srcHash = (Get-FileHash -LiteralPath $_.Fullname -Algorithm SHA256).Hash
            $destHash = (Get-FileHash -LiteralPath $destPath -Algorithm SHA256).Hash

            $change = $srcHash -ne $destHash
        }

        if ($change) {
            Write-Verbose -Message "Installing $($_.Name) to '$pwshDir'"

            if (Test-Path -LiteralPath $destPath) {
                Write-Verbose -Message "Creating backup of $($_.Name) to $($_.Name).bak"
                Copy-Item -LiteralPath $destPath -Destination "$($destPath).bak" -Force
            }

            Copy-Item -LiteralPath $_.Fullname -Destination $destPath
            $notify = $true
        }
    }

    # These symlinks are either no longer needed or we set them to our own path.
    Get-Item -Path (Join-Path -Path $pwshDir -ChildPath 'lib*.so*') |
        Where-Object { $_.Name -match 'lib(ssl|crypto)\.so.*' } |
        ForEach-Object -Process {
            Write-Verbose -Message "Removing existing symlink '$($_.FullName)'"
            $_ | Remove-Item -Force
        }

    $hostInfo.LibCrypto, $hostInfo.LibSSL | ForEach-Object -Process {
        if (-not $_) {
            return
        }

        $srcPath = Join-Path -Path $pwshDir -ChildPath $_.Source
        $create = $true
        $srcLink = Get-Item -LiteralPath $srcPath -ErrorAction SilentlyContinue
        if ($srcLink) {
            if ($srcLink.Target -ne $_.Target) {
                $srcLink | Remove-Item -Force
            }
            else {
                $create = $false
            }
        }

        if ($create) {
            Write-Verbose -Message "Creating symbolic link '$srcPath' -> '$($_.Target)'"
            New-Item -Path $srcPath -ItemType SymbolicLink -Value $_.Target | Out-Null
        }
    }

    if ($notify) {
        $msg = 'WSMan libs have been installed, please restart your PowerShell session to enable it in PowerShell'
        Write-Warning -Message $msg
    }
}

Function Register-TrustedCertificate {
    [CmdletBinding(SupportsShouldProcess=$true, DefaultParameterSetName='Path')]
    param (
        [String]
        $Name,

        [Parameter(Mandatory=$true, ParameterSetName='Path', ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true)]
        [SupportsWildcards()]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Path,

        [Parameter(Mandatory=$true, ParameterSetName='LiteralPath', ValueFromPipelineByPropertyName=$true)]
        [Alias('PSPath')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $LiteralPath,

        [Parameter(Mandatory=$true, ParameterSetName='Certificate', ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true)]
        [X509CertificateChainAttribute()]
        [X509Certificate2Collection]
        $Certificate
    )

    begin {
        $failed = $false

        $certExtension = 'pem'
        $certPath, $refreshCommand = if ($IsMacOS) {
            Write-Verbose -Message "Begin certificate registration for 'macOS'"

            # macOS is special, we don't use the builtin LibreSSL setup and rely on brew or port to provide
            # OpenSSL. This means the path to the cert dir could change at any point in the future and we can't
            # rely on default system locations. Instead we determine the path to the libssl.dylib library and use
            # that to PInvoke the OPENSSLDIR value that it has registered. If that fails then fallback to what
            # should be the brew default '/user/local/etc/openssl@1.1/certs'.
            $openSSLInfo = Get-MacOSOpenSSL
            if (-not $openSSLInfo) {
                $msg = "Failed to find valid macOS OpenSSL package usable by PSWSMan"
                Write-Error -Message $msg -Category ObjectNotFound
                $failed = $true
                return
            }

            $libSSL = $openSSLInfo.LibSSL
            $opensslPath = Split-Path -Path (Split-Path $libSSL -Parent) -Parent
            $opensslBin = Join-Path -Path $opensslPath -ChildPath bin
            $cRehash = Join-Path -Path $opensslBin -ChildPath c_rehash

            $certDirectory = (Get-OpenSSLInfo -LibSSL $libSSL).SSLDir
            if (-not $certDirectory) {
                $certDirectory = '/usr/local/etc/openssl@1.1'
            }

            (Join-Path -Path $certDirectory -ChildPath certs), $cRehash
        }
        else {
            $distribution = Get-DistributionInfo
            Write-Verbose -Message "Begin certificate registration for '$($distribution.Name)'"

            $distroIds = [System.CollEctions.Generic.HashSet[String]]::new()
            if ($distribution.Info.ID) {
                [void]$distroIds.Add($distribution.Info.ID)
            }
            if ($distribution.Info.ID_LIKE) {
                $distribution.Info.ID_LIKE -split " " | ForEach-Object { [void]$distroIds.Add($_) }
            }
            Write-Verbose -Message "Checking for known ids in '$($distroIds -join "', '")'"

            if ('centos' -in $distroIds -or 'fedora' -in $distroIds -or 'rhel' -in $distroIds) {
                '/etc/pki/ca-trust/source/anchors', 'update-ca-trust extract'
            }
            elseif ('arch' -in $distroIds) {
                '/etc/ca-certificates/trust-source/anchors', 'update-ca-trust extract'
            }
            elseif ('alpine' -in $distroIds -or 'debian' -in $distroIds -or 'ubuntu' -in $distroIds) {
                # While the format of the file is the same, these distributions expect the files to have a .crt extension.
                $certExtension = 'crt'
                '/usr/local/share/ca-certificates', 'update-ca-certificates'
            }
            else {
                Write-Error -Message "Failed to determine cert setup information for current host" -Category InvalidOperation
                $failed = $true
                return
            }
        }
        Write-Verbose "Trust directory '$certPath' - Refresh command '$refreshCommand'"

        # We create the child dir if it doesn't exist but we want the parent to at least exist
        $parentDir = Split-Path $certPath -Parent
        if (-not (Test-Path -LiteralPath $parentDir)) {
            $msg = "Failed to find the expected cert trust parent dir at '$parentDir'"
            Write-Error -Message $msg -Category ObjectNotFound
            $failed = $true
            return
        }

        # Store the pem files
        $chainPems = [Collections.Generic.List[String]]@()
    }

    process {
        # Safeguard in case the begin block failed
        if ($failed) {
            return
        }

        $header = '-----BEGIN CERTIFICATE-----'
        $footer = '-----END CERTIFICATE-----'

        if ($PSCmdlet.ParameterSetName -in @('Path', 'LiteralPath')) {
            $Certificate = [X509Certificate2Collection]::new()
            $filePaths = [Collections.Generic.List[String]]@()

            if ($PSCmdlet.ParameterSetName -eq 'Path') {
                $provider = $null
                foreach ($rawPath in $Path) {
                    $filePaths.AddRange($PSCmdlet.GetResolvedProviderPathFromPSPath($rawPath, [ref]$provider))
                }
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
                $filePaths.Add($PSCmdlet.GetUnresolvedProviderPathFromPSPath($LiteralPath))
            }

            foreach ($filePath in $filePaths) {
                Write-Verbose -Message "Processing input certificate at '$filePath'"
                if (-not (Test-Path -LiteralPath $filePath)) {
                    Write-Error -Message "Certificate at '$filePath' does not exist." -Category ObjectNotFound
                    continue
                }

                # X509Certificate2Collection.Import() can be temperamental when trying to load multi-pem files.
                # Instead detect if it's a PEM file and load all the certs manually.
                $rawCertContent = Get-Content -LiteralPath $filePath

                if ($header -in $rawCertContent -and $footer -in $rawCertContent) {
                    foreach ($line in $rawCertContent) {
                        if (-not $line -or $line -eq $header) {
                            $currentCert = [Text.StringBuilder]::new()
                        }
                        elseif ($line -eq $footer) {
                            $certBytes = [Convert]::FromBase64String($currentCert.ToString())
                            $cert = [X509Certificate2]::new($certBytes)
                            $null = $Certificate.Add($cert)
                        }
                        else {
                            $null = $currentCert.Append($line)
                        }
                    }
                }
                else {
                    $Certificate.Import($filePath)
                }
                Write-Verbose -Message "Found $($Certificate.Count) cert(s) at '$filePath'"
            }
        }

        foreach ($cert in $Certificate) {
            Write-Verbose -Message "Processing certificate Subject: '$($cert.Subject)', Thumbprint: $($cert.Thumbprint)"
            $certBytes = $cert.Export([X509ContentType]::Cert)
            $certB64 = [Convert]::ToBase64String($certBytes, [Base64FormattingOptions]::InsertLineBreaks)
            $certB64 = $certB64 -replace "`r`n", "`n"
            $chainPems.Add("$header`n$certB64`n$footer")
        }
    }

    end {
        # Safeguard in case the begin block failed
        if ($failed) {
            return
        }
        if (-not $chainPems) {
            Write-Verbose -Message "No certificates found to import"
            return
        }

        $tempFile = [IO.Path]::GetTempFileName()
        try {
            foreach ($pem in $chainPems) {
                Add-Content -LiteralPath $tempFile -Value $pem
            }

            if (-not $Name) {
                $hashStr = (Get-FileHash -LiteralPath $tempFile -Algorithm SHA256).Hash
                $Name = "PSWSMan-$hashStr"
            }

            if (-not (Test-Path $certPath)) {
                if ($PSCmdlet.ShouldProcess($certPath, 'Create')) {
                    Write-Verbose -Message "Creating trust cert dir at '$certPath'"
                    New-Item -Path $certPath -ItemType Directory | Out-Null
                }
            }

            $destCertPath = Join-Path -Path $certPath -ChildPath "$Name.$certExtension"
            if ($PSCmdlet.ShouldProcess($destCertPath, 'Register')) {
                Write-Verbose -Message "Creating trust cert file at '$destCertPath'"
                Copy-Item -LiteralPath $tempFile -Destination $destCertPath -Force

                # The file must be executable
                pswsman_exec chmod 755 $destCertPath | Out-Null

                # The command to run may contain argument, just use Invoke-Expression as the input is statically defined.
                Write-Verbose -Message "Refreshing the trusted certificate directory with '$refreshCommand'"
                Invoke-Expression -Command $refreshCommand
            }
        } finally {
            Remove-Item -LiteralPath $tempFile -Force
        }
    }
}

$export = @{
    Function = @(
        'Install-WSMan',
        'Register-TrustedCertificate'
    )
    Cmdlet = (
        'Disable-WSManCertVerification',
        'Enable-WSManCertVerification',
        'Get-WSManVersion'
    )
}
Export-ModuleMember @export
