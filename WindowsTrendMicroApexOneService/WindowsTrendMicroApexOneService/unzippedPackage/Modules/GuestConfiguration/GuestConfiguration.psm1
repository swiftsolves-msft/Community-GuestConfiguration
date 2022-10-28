using namespace System.IO.Compression.ZipFile
#Region './prefix.ps1' 0
Set-StrictMode -Version latest
$ErrorActionPreference = 'Stop'

Import-Module $PSScriptRoot/Modules/GuestConfigPath -Force
Import-Module $PSScriptRoot/Modules/DscOperations -Force
Import-Module $PSScriptRoot/Modules/GuestConfigurationPolicy -Force
Import-LocalizedData -BaseDirectory $PSScriptRoot -FileName GuestConfiguration.psd1 -BindingVariable GuestConfigurationManifest

if ($IsLinux -and (
    $PSVersionTable.PSVersion.Major -lt 7 -or
    ($PSVersionTable.PSVersion.Major -eq 7 -and $PSVersionTable.PSVersion.Minor -lt 2)
    ))
{
    throw 'The Linux agent requires at least PowerShell v7.2.preview.6 to support the DSC subsystem.'
}

$currentCulture = [System.Globalization.CultureInfo]::CurrentCulture
if (($currentCulture.Name -eq 'en-US-POSIX') -and ($(Get-OSPlatform) -eq 'Linux'))
{
    Write-Warning "'$($currentCulture.Name)' Culture is not supported, changing it to 'en-US'"
    # Set Culture info to en-US
    [System.Globalization.CultureInfo]::CurrentUICulture = [System.Globalization.CultureInfo]::new('en-US')
    [System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]::new('en-US')
}

#inject version info to GuestConfigPath.psm1
InitReleaseVersionInfo $GuestConfigurationManifest.moduleVersion
#EndRegion './prefix.ps1' 28
#Region './Enum/AssignmentType.ps1' 0
enum AssignmentType
{
    ApplyAndAutoCorrect
    ApplyAndMonitor
    Audit
}
#EndRegion './Enum/AssignmentType.ps1' 7
#Region './Enum/PackageType.ps1' 0
enum PackageType
{
    Audit
    AuditAndSet
}
#EndRegion './Enum/PackageType.ps1' 6
#Region './Private/Compress-ArchiveByDirectory.ps1' 0
#using namespace System.IO.Compression.ZipFile

<#
    .SYNOPSIS
        Create an Zip file from a Directory, including hidden files and folders.

    .DESCRIPTION
        The Compress-Archive is not copying hidden files and Directory by default,
        and it can be tricky to make it work without losing the Directory structure.
        However the `[System.IO.Compression.ZipFile]::CreateFromDirectory()` method
        makes it possible, and this function is a wrapper for it.
        The reason for creating a wrapper is to simplify testing via mocking.

    .PARAMETER Path
        Path of the File or Directory to compress.

    .PARAMETER DestinationPath
        Destination file to Zip the Directory into.

    .PARAMETER CompressionLevel
        Compression level between Fastest, Optimal, and NoCompression.

    .PARAMETER IncludeBaseDirectory
        Whether you want the zip to include the Directory and its content in the zip,
        or if you only want the content of the Directory to be at the zip's root (default).

    .PARAMETER Force
        Delete the destination file if it already exists.

    .EXAMPLE
        PS C:\> Compress-ArchiveByDirectory -Path C:\MyDir -DestinationPath C:\MyDir.zip -CompressionLevel Fastest -IncludeBaseDirectory -Force

#>
function Compress-ArchiveByDirectory
{
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]
    [OutputType([void])]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter(Mandatory = $true)]
        [System.String]
        $DestinationPath,

        [Parameter()]
        [System.IO.Compression.CompressionLevel]
        $CompressionLevel = [System.IO.Compression.CompressionLevel]::Fastest,

        [Parameter()]
        [System.Management.Automation.SwitchParameter]
        $IncludeBaseDirectory,

        [Parameter()]
        [System.Management.Automation.SwitchParameter]
        $Force
    )

    if (-not  (Split-Path -IsAbsolute -Path $DestinationPath))
    {
        $DestinationPath = Join-Path -Path (Get-Location -PSProvider fileSystem) -ChildPath $DestinationPath
    }

    if ($PSBoundParameters.ContainsKey('Force') -and $true -eq $PSBoundParameters['Force'])
    {
        if ((Test-Path -Path $DestinationPath) -and $PSCmdlet.ShouldProcess("Deleting Zip file '$DestinationPath'.", $DestinationPath, 'Remove-Item -Force'))
        {
            Remove-Item -Force $DestinationPath -ErrorAction Stop
        }
    }

    if ($PSCmdlet.ShouldProcess("Zipping '$Path' to '$DestinationPath' with compression level '$CompressionLevel', includig base dir: '$($IncludeBaseDirectory.ToBool())'.", $Path, 'ZipFile'))
    {
        [System.IO.Compression.ZipFile]::CreateFromDirectory($Path, $DestinationPath, $CompressionLevel, $IncludeBaseDirectory.ToBool())
    }
}
#EndRegion './Private/Compress-ArchiveByDirectory.ps1' 81
#Region './Private/Get-GuestConfigurationPackageFromUri.ps1' 0
function Get-GuestConfigurationPackageFromUri
{
    [CmdletBinding()]
    [OutputType([System.Io.FileInfo])]
    param
    (
        [Parameter()]
        [Uri]
        [ValidateScript({([Uri]$_).Scheme -match '^http'})]
        [Alias('Url')]
        $Uri
    )

    # Abstracting this in another function as we may want to support Proxy later.
    $tempFileName = [io.path]::GetTempFileName()
    $null = [System.Net.WebClient]::new().DownloadFile($Uri, $tempFileName)

    # The zip can be PackageName_0.2.3.zip, so we really need to look at the MOF to find its name.
    $packageName = Get-GuestConfigurationPackageNameFromZip -Path $tempFileName

    Move-Item -Path $tempFileName -Destination ('{0}.zip' -f $packageName) -Force -PassThru
}
#EndRegion './Private/Get-GuestConfigurationPackageFromUri.ps1' 23
#Region './Private/Get-GuestConfigurationPackageMetaConfig.ps1' 0
function Get-GuestConfigurationPackageMetaConfig
{
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path
    )

    $packageName = Get-GuestConfigurationPackageName -Path $Path
    $metadataFileName = '{0}.metaconfig.json' -f $packageName
    $metadataFile = Join-Path -Path $Path -ChildPath $metadataFileName

    if (Test-Path -Path $metadataFile)
    {
        Write-Debug -Message "Loading metadata from meta config file '$metadataFile'."
        $metadata = Get-Content -raw -Path $metadataFile | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    }
    else
    {
        $metadata = @{}
    }

    #region Extra meta file until Agent supports one unique metadata file
    $extraMetadataFileName = 'extra.{0}' -f $metadataFileName
    $extraMetadataFile = Join-Path -Path $Path -ChildPath $extraMetadataFileName

    if (Test-Path -Path $extraMetadataFile)
    {
        Write-Debug -Message "Loading extra metadata from extra meta file '$extraMetadataFile'."
        $extraMetadata = Get-Content -raw -Path $extraMetadataFile | ConvertFrom-Json -AsHashtable -ErrorAction Stop

        foreach ($extraKey in $extraMetadata.keys)
        {
            if (-not $metadata.ContainsKey($extraKey))
            {
                $metadata[$extraKey] = $extraMetadata[$extraKey]
            }
            else
            {
                Write-Verbose -Message "The metadata '$extraKey' is already defined in '$metadataFile'."
            }
        }
    }
    #endregion

    return $metadata
}
#EndRegion './Private/Get-GuestConfigurationPackageMetaConfig.ps1' 51
#Region './Private/Get-GuestConfigurationPackageMetadataFromZip.ps1' 0
function Get-GuestConfigurationPackageMetadataFromZip
{
    [CmdletBinding()]
    [OutputType([PSObject])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Io.FileInfo]
        $Path
    )

    $Path = [System.IO.Path]::GetFullPath($Path) # Get Absolute path as .Net methods don't like relative paths.

    try
    {
        $tempFolderPackage = Join-Path -Path ([io.path]::GetTempPath()) -ChildPath ([guid]::NewGuid().Guid)
        Expand-Archive -LiteralPath $Path -DestinationPath $tempFolderPackage -Force
        Get-GuestConfigurationPackageMetaConfig -Path $tempFolderPackage
    }
    finally
    {
        # Remove the temporarily extracted package
        Remove-Item -Force -Recurse $tempFolderPackage -ErrorAction SilentlyContinue
    }
}
#EndRegion './Private/Get-GuestConfigurationPackageMetadataFromZip.ps1' 26
#Region './Private/Get-GuestConfigurationPackageName.ps1' 0
function Get-GuestConfigurationPackageName
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Io.FileInfo]
        $Path
    )

    $Path = [System.IO.Path]::GetFullPath($Path) # Get Absolute path as .Net method don't like relative paths.
    # Make sure we only get the MOF which is at the root of the package
    $mofFile = @() + (Get-ChildItem -Path (Join-Path -Path $Path -ChildPath *.mof) -File -ErrorAction Stop)

    if ($mofFile.Count -ne 1)
    {
        throw "Invalid GuestConfiguration Package at '$Path'. Found $($mofFile.Count) mof files."
        return
    }
    else
    {
        Write-Debug -Message "Found the MOF '$($moffile)' in $Path."
    }

    return ([System.Io.Path]::GetFileNameWithoutExtension($mofFile[0]))
}
#EndRegion './Private/Get-GuestConfigurationPackageName.ps1' 28
#Region './Private/Get-GuestConfigurationPackageNameFromZip.ps1' 0
function Get-GuestConfigurationPackageNameFromZip
{
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [System.Io.FileInfo]
        $Path
    )

    $Path = [System.IO.Path]::GetFullPath($Path) # Get Absolute path as .Net method don't like relative paths.

    try
    {
        $zipRead = [IO.Compression.ZipFile]::OpenRead($Path)
        # Make sure we only get the MOF which is at the root of the package
        $mofFile = @() + $zipRead.Entries.FullName.Where({((Split-Path -Leaf -Path $_) -eq $_) -and $_ -match '\.mof$'})
    }
    finally
    {
        # Close the zip so we can move it.
        $zipRead.Dispose()
    }

    if ($mofFile.count -ne 1)
    {
        throw "Invalid policy package, failed to find unique dsc document in policy package downloaded from '$Uri'."
    }

    return ([System.Io.Path]::GetFileNameWithoutExtension($mofFile[0]))
}
#EndRegion './Private/Get-GuestConfigurationPackageNameFromZip.ps1' 32
#Region './Private/Update-GuestConfigurationPackageMetaconfig.ps1' 0
function Update-GuestConfigurationPackageMetaconfig
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $MetaConfigPath,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Key,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Value
    )

    $metadataFile = $MetaConfigPath

    #region Write extra metadata on different file until the GC Agents supports it
    if ($Key -notin @('debugMode','ConfigurationModeFrequencyMins','configurationMode'))
    {
        $fileName = Split-Path -Path $MetadataFile -Leaf
        $filePath = Split-Path -Path $MetadataFile -Parent
        $metadataFileName = 'extra.{0}' -f $fileName

        $metadataFile = Join-Path -Path $filePath -ChildPath $metadataFileName
    }
    #endregion

    Write-Debug -Message "Updating the file '$metadataFile' with key $Key = '$Value'."

    if (Test-Path -Path $metadataFile)
    {
        $metaConfigObject = Get-Content -Raw -Path $metadataFile | ConvertFrom-Json -AsHashtable
        $metaConfigObject[$Key] = $Value
        $metaConfigObject | ConvertTo-Json | Out-File -Path $metadataFile -Encoding ascii -Force
    }
    else
    {
        @{
            $Key = $Value
        } | ConvertTo-Json | Out-File -Path $metadataFile -Encoding ascii -Force
    }
}
#EndRegion './Private/Update-GuestConfigurationPackageMetaconfig.ps1' 47
#Region './Public/Get-GuestConfigurationPackageComplianceStatus.ps1' 0
function Get-GuestConfigurationPackageComplianceStatus
{
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String]
        $Path,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Hashtable[]]
        $Parameter = @()
    )

    begin
    {
        # Determine if verbose is enabled to pass down to other functions
        $verbose = ($PSBoundParameters.ContainsKey("Verbose") -and ($PSBoundParameters["Verbose"] -eq $true))
        $systemPSModulePath = [Environment]::GetEnvironmentVariable("PSModulePath", "Process")
        $gcBinPath = Get-GuestConfigBinaryPath
        $guestConfigurationPolicyPath = Get-GuestConfigPolicyPath

    }

    process
    {
        try
        {
            if ($PSBoundParameters.ContainsKey('Force') -and $Force)
            {
                $withForce = $true
            }
            else
            {
                $withForce = $false
            }

            $packagePath = Install-GuestConfigurationPackage -Path $Path -Force:$withForce

            Write-Debug -Message "Looking into Package '$PackagePath' for MOF document."

            $packageName = Get-GuestConfigurationPackageName -Path $PackagePath

            # Confirm mof exists
            $packageMof = Join-Path -Path $packagePath -ChildPath "$packageName.mof"
            $dscDocument = Get-Item -Path $packageMof -ErrorAction 'SilentlyContinue'

            if (-not $dscDocument)
            {
                throw "Invalid Guest Configuration package, failed to find dsc document at '$packageMof' path."
            }

            # update configuration parameters
            if ($Parameter.Count -gt 0)
            {
                Update-MofDocumentParameters -Path $dscDocument.FullName -Parameter $Parameter
            }

            # Publish policy package
            Publish-DscConfiguration -ConfigurationName $packageName -Path $PackagePath -Verbose:$verbose

            # Set LCM settings to force load powershell module.
            $metaConfigPath = Join-Path -Path $PackagePath -ChildPath "$packageName.metaconfig.json"
            Update-GuestConfigurationPackageMetaconfig -metaConfigPath $metaConfigPath -Key 'debugMode' -Value 'ForceModuleImport'

            Set-DscLocalConfigurationManager -ConfigurationName $packageName -Path $PackagePath -Verbose:$verbose


            # Clear Inspec profiles
            Remove-Item -Path $(Get-InspecProfilePath) -Recurse -Force -ErrorAction SilentlyContinue

            $getResult = @()
            $getResult = $getResult + (Get-DscConfiguration -ConfigurationName $packageName -Verbose:$verbose)
            return $getResult
        }
        finally
        {
            $env:PSModulePath = $systemPSModulePath
        }
    }
}
#EndRegion './Public/Get-GuestConfigurationPackageComplianceStatus.ps1' 83
#Region './Public/Install-GuestConfigurationAgent.ps1' 0
function Install-GuestConfigurationAgent
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter()]
        [System.Management.Automation.SwitchParameter]
        $Force
    )

    # Unzip Guest Configuration binaries
    $gcBinPath = Get-GuestConfigBinaryPath
    $gcBinRootPath = Get-GuestConfigBinaryRootPath
    $OsPlatform = Get-OSPlatform
    if ($PSBoundParameters.ContainsKey('Force') -and $PSBoundParameters['Force'])
    {
        $withForce = $true
    }
    else
    {
        $withForce = $false
    }

    if ((-not (Test-Path -Path $gcBinPath)) -or $withForce)
    {
        # Clean the bin folder
        Write-Verbose -Message "Removing existing installation from '$gcBinRootPath'."
        Remove-Item -Path $gcBinRootPath'\*' -Recurse -Force -ErrorAction SilentlyContinue
        $zippedBinaryPath = Join-Path -Path $(Get-GuestConfigurationModulePath) -ChildPath 'bin'

        if ($OsPlatform -eq 'Windows')
        {
            $zippedBinaryPath = Join-Path -Path $zippedBinaryPath -ChildPath 'DSC_Windows.zip'
        }
        else
        {
            # Linux zip package contains an additional DSC folder
            # Remove DSC folder from binary path to avoid two nested DSC folders.
            $null = New-Item -ItemType Directory -Force -Path $gcBinPath
            $gcBinPath = (Get-Item -Path $gcBinPath).Parent.FullName
            $zippedBinaryPath = Join-Path $zippedBinaryPath 'DSC_Linux.zip'
        }

        Write-Verbose -Message "Extracting '$zippedBinaryPath' to '$gcBinPath'."
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zippedBinaryPath, $gcBinPath)

        if ($OsPlatform -ne 'Windows')
        {
            # Fix for “LTTng-UST: Error (-17) while registering tracepoint probe. Duplicate registration of tracepoint probes having the same name is not allowed.”
            Get-ChildItem -Path $gcBinPath -Filter libcoreclrtraceptprovider.so -Recurse | ForEach-Object {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            }

            Get-ChildItem -Path $gcBinPath -Filter *.sh -Recurse | ForEach-Object -Process {
                chmod @('+x', $_.FullName)
            }
        }

	# Save config file
    $gcConfigPath = Join-Path (Get-GuestConfigBinaryPath) 'gc.config'
    '{ "SaveLogsInJsonFormat": true, "DoNotSendReport": true}' | Out-File -Path $gcConfigPath -Encoding ascii -Force

    if ($OsPlatform -ne 'Windows')
    {
        # Give root user permission to execute gc_worker
        chmod 700 (Get-GuestConfigWorkerBinaryPath)
    }
}
    else
    {
        Write-Verbose -Message "Guest Configuration Agent binaries already installed at '$gcBinPath', skipping."
    }
}
#EndRegion './Public/Install-GuestConfigurationAgent.ps1' 75
#Region './Public/Install-GuestConfigurationPackage.ps1' 0
<#
    .SYNOPSIS
        Installs a Guest Configuration policy package.

    .Parameter Package
        Path or Uri of the Guest Configuration package zip.

    .Parameter Force
        Force installing over an existing package, even if it already exists.

    .Example
        Install-GuestConfigurationPackage -Path ./custom_policy/WindowsTLS.zip

        Install-GuestConfigurationPackage -Path ./custom_policy/AuditWindowsService.zip -Force

    .OUTPUTS
        The path to the installed Guest Configuration package.
#>

function Install-GuestConfigurationPackage
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Path,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [System.Management.Automation.SwitchParameter]
        $Force
    )

    $osPlatform = Get-OSPlatform

    if ($osPlatform -eq 'MacOS')
    {
        throw 'The Install-GuestConfigurationPackage cmdlet is not supported on MacOS'
    }


    $verbose = $VerbosePreference -ne 'SilentlyContinue' -or ($PSBoundParameters.ContainsKey('Verbose') -and ($PSBoundParameters['Verbose'] -eq $true))
    $systemPSModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', 'Process')
    $guestConfigurationPolicyPath = Get-GuestConfigPolicyPath

    try
    {
        # Unzip Guest Configuration binaries if missing
        Install-GuestConfigurationAgent -verbose:$verbose

        # Resolve the zip (to temp folder if URI)
        if (($Path -as [uri]).Scheme -match '^http')
        {
            # Get the package from URI to a temp folder
            $PackageZipPath = (Get-GuestConfigurationPackageFromUri -Uri $Path -Verbose:$verbose).ToString()
        }
        elseif ((Test-Path -PathType 'Leaf' -Path $Path) -and $Path -match '\.zip$')
        {
            $PackageZipPath = (Resolve-Path -Path $Path).ToString()
        }
        else
        {
            # The $Path parameter is not a valid path or URL
            throw "'$Path' is not a valid path to the package. Please provide the path to the Zip or the URL to download the package from."
        }

        Write-Debug -Message "Getting package name from '$PackageZipPath'."
        $packageName = Get-GuestConfigurationPackageNameFromZip -Path $PackageZipPath
        $packageZipMetadata = Get-GuestConfigurationPackageMetadataFromZip -Path $PackageZipPath -Verbose:$verbose
        $installedPackagePath = Join-Path -Path $guestConfigurationPolicyPath -ChildPath $packageName
        $isPackageAlreadyInstalled = $false

        if (Test-Path -Path $installedPackagePath)
        {
            Write-Debug -Message "The Package '$PackageName' exists at '$installedPackagePath'. Checking version..."
            $installedPackageMetadata = Get-GuestConfigurationPackageMetaConfig -Path $installedPackagePath -Verbose:$verbose

            # None of the packages are versioned or the versions match, we're good
            if (-not ($installedPackageMetadata.ContainsKey('Version') -or $packageZipMetadata.Contains('Version')) -or
                ($installedPackageMetadata.ContainsKey('Version') -ne $packageZipMetadata.Contains('Version')) -or # to avoid next statement
                $installedPackageMetadata.Version -eq $packageZipMetadata.Version)
            {
                $isPackageAlreadyInstalled = $true
                Write-Debug -Message ("Package '{0}{1}' is installed." -f $PackageName,($packageZipMetadata.Contains('Version') ? "_$($packageZipMetadata['Version'])" : ''))
            }
            else
            {
                Write-Verbose -Message "Package '$packageName' was found at version '$($installedPackageMetadata.Version)' but we're expecting '$($packageZipMetadata.Version)'."
            }
        }

        if ($PSBoundParameters.ContainsKey('Force') -and $PSBoundParameters['Force'])
        {
            $withForce = $true
        }
        else
        {
            $withForce = $false
        }

        if ((-not $isPackageAlreadyInstalled) -or $withForce)
        {
            Write-Debug -Message "Removing existing package at '$installedPackagePath'."
            Remove-Item -Path $installedPackagePath -Recurse -Force -ErrorAction SilentlyContinue
            $null = New-Item -ItemType Directory -Force -Path $installedPackagePath
            # Unzip policy package
            Write-Verbose -Message "Unzipping the Guest Configuration Package to '$installedPackagePath'."
            Expand-Archive -LiteralPath $PackageZipPath -DestinationPath $installedPackagePath -ErrorAction Stop -Force
        }
        else
        {
            Write-Verbose -Message "Package is already installed at '$installedPackagePath', skipping install."
        }

        # Clear Inspec profiles
        Remove-Item -Path (Get-InspecProfilePath) -Recurse -Force -ErrorAction SilentlyContinue
    }
    finally
    {
        $env:PSModulePath = $systemPSModulePath

        # If we downloaded the Zip file from URI to temp folder, do cleanup
        if (($Path -as [uri]).Scheme -match '^http')
        {
            Write-Debug -Message "Removing the Package zip at '$PackageZipPath' that was downloaded from URI."
            Remove-Item -Force -ErrorAction SilentlyContinue -Path $PackageZipPath
        }
    }

    return $installedPackagePath
}
#EndRegion './Public/Install-GuestConfigurationPackage.ps1' 134
#Region './Public/New-GuestConfigurationFile.ps1' 0

<#
    .SYNOPSIS
        Automatically generate a MOF file based on
        files discovered in a folder path

        This command is optional and is intended to
        reduce the number of steps needed when
        using other language abstractions such as Pester

        When creating packages from compiled DSC
        configurations, you do not need to run this command

    .Parameter Source
        Location of the folder containing content

    .Parameter Path
        Location of the folder containing content

    .Parameter Format
        Format of the files (currently only Pester is supported)

    .Parameter Force
        When specified, will overwrite the destination file if it already exists

    .Example
        New-GuestConfigurationFile -Path ./Scripts

    .OUTPUTS
        Return the path of the generated configuration MOF file
#>

function New-GuestConfigurationFile
{
    [CmdletBinding()]
    [Experimental("GuestConfiguration.Pester", "Show")]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name,

        [Parameter(Position = 1, Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Source,

        [Parameter(Position = 2, Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Path,

        [Parameter(Position = 3, ValueFromPipelineByPropertyName = $true)]
        [System.String]
        $Format = 'Pester',

        [Parameter()]
        [System.Management.Automation.SwitchParameter]
        $Force
    )

    $return = [PSCustomObject]@{
        Name = ''
        Configuration = ''
    }

    if ('Pester' -eq $Format)
    {
        Write-Warning -Message 'Guest Configuration: Pester content is an expiremental feature and not officially supported'
        if ([ExperimentalFeature]::IsEnabled("GuestConfiguration.Pester"))
        {
            $ConfigMOF = New-MofFileforPester -Name $Name -PesterScriptsPath $Source -Path $Path -Force:$Force
            $return.Name = $Name
            $return.Configuration = $ConfigMOF.Path
        }
        else
        {
            throw 'Before you can use Pester content, you must enable the experimental feature in PowerShell.'
        }
    }

    return $return
}
#EndRegion './Public/New-GuestConfigurationFile.ps1' 86
#Region './Public/New-GuestConfigurationPackage.ps1' 0

<#
    .SYNOPSIS
        Creates a Guest Configuration policy package.

    .Parameter Name
        Guest Configuration package name.

    .Parameter Version
        Guest Configuration package Version (SemVer).

    .Parameter Configuration
        Compiled DSC configuration document full path.

    .Parameter Path
        Output folder path.
        This is an optional parameter. If not specified, the package will be created in the current directory.

    .Parameter ChefInspecProfilePath
        Chef profile path, supported only on Linux.

    .Parameter Type
        Specifies whether or not package will support AuditAndSet or only Audit. Set to Audit by default.

    .Parameter Force
        Overwrite the package files if already present.

    .Example
        New-GuestConfigurationPackage -Name WindowsTLS -Configuration ./custom_policy/WindowsTLS/localhost.mof -Path ./git/repository/release/policy/WindowsTLS

    .OUTPUTS
        Return name and path of the new Guest Configuration Policy package.
#>

function New-GuestConfigurationPackage
{
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName = 'Configuration', ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Configuration,

        [Parameter(Position = 2, ParameterSetName = 'Configuration', ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [SemVer]
        $Version,

        [Parameter(ParameterSetName = 'Configuration')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ChefInspecProfilePath,

        [Parameter(ParameterSetName = 'Configuration')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $FilesToInclude,

        [Parameter()]
        [System.String]
        $Path = '.',

        [Parameter()]
        [PackageType]
        $Type = 'Audit',

        [Parameter()]
        [System.Management.Automation.SwitchParameter]
        $Force
    )

    if (-not (Get-Variable -Name Type -ErrorAction SilentlyContinue))
    {
        $Type = 'Audit'
    }

    $verbose = ($PSBoundParameters.ContainsKey("Verbose") -and ($PSBoundParameters["Verbose"] -eq $true))
    $stagingPackagePath = Join-Path -Path (Join-Path -Path $Path -ChildPath $Name) -ChildPath 'unzippedPackage'
    $unzippedPackageDirectory = New-Item -ItemType Directory -Force -Path $stagingPackagePath
    $Configuration = Resolve-Path -Path $Configuration

    if (-not (Test-Path -Path $Configuration -PathType Leaf))
    {
        throw "Invalid mof file path, please specify full file path for dsc configuration in -Configuration parameter."
    }

    Write-Verbose -Message "Creating Guest Configuration package in temporary directory '$unzippedPackageDirectory'"

    # Verify that only supported resources are used in DSC configuration.
    Test-GuestConfigurationMofResourceDependencies -Path $Configuration -Verbose:$verbose

    # Save DSC configuration to the temporary package path.
    $configMOFPath = Join-Path -Path $unzippedPackageDirectory -ChildPath "$Name.mof"
    Save-GuestConfigurationMofDocument -Name $Name -SourcePath $Configuration -DestinationPath $configMOFPath -Verbose:$verbose

    # Copy DSC resources
    Copy-DscResources -MofDocumentPath $Configuration -Destination $unzippedPackageDirectory -Verbose:$verbose -Force:$Force

    # Modify metaconfig file
    $metaConfigPath = Join-Path -Path $unzippedPackageDirectory -ChildPath "$Name.metaconfig.json"
    Update-GuestConfigurationPackageMetaconfig -metaConfigPath $metaConfigPath -Key 'Type' -Value $Type.ToString()

    if ($PSBoundParameters.ContainsKey('Version'))
    {
        Update-GuestConfigurationPackageMetaconfig -MetaConfigPath $metaConfigPath -key 'Version' -Value $Version.ToString()
    }

    if (-not [string]::IsNullOrEmpty($ChefInspecProfilePath))
    {
        # Copy Chef resource and profiles.
        Copy-ChefInspecDependencies -PackagePath $unzippedPackageDirectory -Configuration $Configuration -ChefInspecProfilePath $ChefInspecProfilePath
    }

    # Copy FilesToInclude
    if (-not [string]::IsNullOrEmpty($FilesToInclude))
    {
        $modulePath = Join-Path $unzippedPackageDirectory 'Modules'
        if (Test-Path $FilesToInclude -PathType Leaf)
        {
            Copy-Item -Path $FilesToInclude -Destination $modulePath  -Force:$Force
        }
        else
        {
            $filesToIncludeFolderName = Get-Item -Path $FilesToInclude
            $FilesToIncludePath = Join-Path -Path $modulePath -ChildPath $filesToIncludeFolderName.Name
            Copy-Item -Path $FilesToInclude -Destination $FilesToIncludePath -Recurse -Force:$Force
        }
    }

    # Create Guest Configuration Package.
    $packagePath = Join-Path -Path $Path -ChildPath $Name
    $null = New-Item -ItemType Directory -Force -Path $packagePath
    $packagePath = Resolve-Path -Path $packagePath
    $packageFilePath = join-path -Path $packagePath -ChildPath "$Name.zip"
    if (Test-Path -Path $packageFilePath)
    {
        Remove-Item -Path $packageFilePath -Force -ErrorAction SilentlyContinue
    }

    Write-Verbose -Message "Creating Guest Configuration package : $packageFilePath."
    Compress-ArchiveByDirectory -Path $unzippedPackageDirectory -DestinationPath $packageFilePath -Force:$Force

    [pscustomobject]@{
        PSTypeName = 'GuestConfiguration.Package'
        Name = $Name
        Path = $packageFilePath
    }
}
#EndRegion './Public/New-GuestConfigurationPackage.ps1' 156
#Region './Public/New-GuestConfigurationPolicy.ps1' 0

<#
    .SYNOPSIS
        Creates Audit, DeployIfNotExists and Initiative policy definitions on specified Destination Path.

    .Parameter ContentUri
        Public http uri of Guest Configuration content package.

    .Parameter DisplayName
        Policy display name.

    .Parameter Description
        Policy description.

    .Parameter Parameter
        Policy parameters.

    .Parameter Version
        Policy version.

    .Parameter Path
        Destination path.

    .Parameter Platform
        Target platform (Windows/Linux) for Guest Configuration policy and content package.
        Windows is the default platform.

    .Parameter Mode
        Defines whether or not the policy is Audit or Deploy. Acceptable values: Audit, ApplyAndAutoCorrect, or ApplyAndMonitor. Audit is the default mode.

    .Parameter Tag
        The name and value of a tag used in Azure.

    .Example
        New-GuestConfigurationPolicy `
                                 -ContentUri https://github.com/azure/auditservice/release/AuditService.zip `
                                 -DisplayName 'Monitor Windows Service Policy.' `
                                 -Description 'Policy to monitor service on Windows machine.' `
                                 -Version 1.0.0.0
                                 -Path ./git/custom_policy
                                 -Tag @{Owner = 'WebTeam'}

        $PolicyParameterInfo = @(
            @{
                Name = 'ServiceName'                                       # Policy parameter name (mandatory)
                DisplayName = 'windows service name.'                      # Policy parameter display name (mandatory)
                Description = "Name of the windows service to be audited." # Policy parameter description (optional)
                ResourceType = "Service"                                   # dsc configuration resource type (mandatory)
                ResourceId = 'windowsService'                              # dsc configuration resource property name (mandatory)
                ResourcePropertyName = "Name"                              # dsc configuration resource property name (mandatory)
                DefaultValue = 'winrm'                                     # Policy parameter default value (optional)
                AllowedValues = @('wscsvc','WSearch','wcncsvc','winrm')    # Policy parameter allowed values (optional)
            })

            New-GuestConfigurationPolicy -ContentUri 'https://github.com/azure/auditservice/release/AuditService.zip' `
                                 -DisplayName 'Monitor Windows Service Policy.' `
                                 -Description 'Policy to monitor service on Windows machine.' `
                                 -Version 1.0.0.0
                                 -Path ./policyDefinitions `
                                 -Parameter $PolicyParameterInfo

    .OUTPUTS
        Return name and path of the Guest Configuration policy definitions.
#>

function New-GuestConfigurationPolicy
{
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Uri]
        $ContentUri,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DisplayName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Description,

        [Parameter()]
        [System.Collections.Hashtable[]]
        $Parameter,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Version]
        $Version = '1.0.0',

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Path,

        [Parameter()]
        [ValidateSet('Windows', 'Linux')]
        [System.String]
        $Platform = 'Windows',

        [Parameter()]
        [AssignmentType]
        $Mode = 'Audit',

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $PolicyId,

        [Parameter()]
        [System.Collections.Hashtable[]]
        $Tag
    )

    # This value must be static for AINE policies due to service configuration
    $Category = 'Guest Configuration'

    try
    {
        $verbose = ($PSBoundParameters.ContainsKey("Verbose") -and ($PSBoundParameters["Verbose"] -eq $true))
        $policyDefinitionsPath = $Path
        $unzippedPkgPath = Join-Path -Path $policyDefinitionsPath -ChildPath 'temp'
        $tempContentPackageFilePath = Join-Path -Path $policyDefinitionsPath -ChildPath 'temp.zip'

        # Update parameter info
        $ParameterInfo = Update-PolicyParameter -Parameter $Parameter

        $null = New-Item -ItemType Directory -Force -Path $policyDefinitionsPath

        # Check if ContentUri is a valid web URI
        if (-not ($null -ne $ContentUri.AbsoluteURI -and $ContentUri.Scheme -match '[http|https]'))
        {
            throw "Invalid ContentUri : $ContentUri. Please specify a valid http URI in -ContentUri parameter."
        }

        # Generate checksum hash for policy content.
        Invoke-WebRequest -Uri $ContentUri -OutFile $tempContentPackageFilePath
        $tempContentPackageFilePath = Resolve-Path $tempContentPackageFilePath
        $contentHash = (Get-FileHash $tempContentPackageFilePath -Algorithm SHA256).Hash
        Write-Verbose "SHA256 Hash for content '$ContentUri' : $contentHash."

        # Get the policy name from policy content.
        Remove-Item $unzippedPkgPath -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force -Path $unzippedPkgPath | Out-Null
        $unzippedPkgPath = Resolve-Path $unzippedPkgPath
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($tempContentPackageFilePath, $unzippedPkgPath)

        $dscDocument = Get-ChildItem -Path $unzippedPkgPath -Filter *.mof -Exclude '*.schema.mof' -Depth 1
        if (-not $dscDocument)
        {
            throw "Invalid policy package, failed to find dsc document in policy package."
        }

        $policyName = [System.IO.Path]::GetFileNameWithoutExtension($dscDocument)

        $packageIsSigned = (($null -ne (Get-ChildItem -Path $unzippedPkgPath -Filter *.cat)) -or
            (($null -ne (Get-ChildItem -Path $unzippedPkgPath -Filter *.asc)) -and ($null -ne (Get-ChildItem -Path $unzippedPkgPath -Filter *.sha256sums))))

        # Determine if policy is AINE or DINE
        if ($Mode -eq "Audit")
        {
            $FileName = 'AuditIfNotExists.json'
        }
        else {
            $FileName = 'DeployIfNotExists.json'
        }

        $PolicyInfo = @{
            FileName                 = $FileName
            DisplayName              = $DisplayName
            Description              = $Description
            Platform                 = $Platform
            ConfigurationName        = $policyName
            ConfigurationVersion     = $Version
            ContentUri               = $ContentUri
            ContentHash              = $contentHash
            AssignmentType           = $Mode
            ReferenceId              = "Deploy_$policyName"
            ParameterInfo            = $ParameterInfo
            UseCertificateValidation = $packageIsSigned
            Category                 = $Category
            Guid                     = $PolicyId
            Tag                      = $Tag
        }

        $null = New-CustomGuestConfigPolicy -PolicyFolderPath $policyDefinitionsPath -PolicyInfo $PolicyInfo -Verbose:$verbose

        [pscustomobject]@{
            PSTypeName = 'GuestConfiguration.Policy'
            Name = $policyName
            Path = $Path
        }
    }
    finally
    {
        # Remove staging content package.
        Remove-Item -Path $tempContentPackageFilePath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $unzippedPkgPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#EndRegion './Public/New-GuestConfigurationPolicy.ps1' 206
#Region './Public/Protect-GuestConfigurationPackage.ps1' 0

<#
    .SYNOPSIS
        Signs a Guest Configuration policy package using certificate on Windows and Gpg keys on Linux.

    .Parameter Path
        Full path of the Guest Configuration package.

    .Parameter Certificate
        'Code Signing' certificate to sign the package. This is only supported on Windows.

    .Parameter PrivateGpgKeyPath
        Private Gpg key path. This is only supported on Linux.

    .Parameter PublicGpgKeyPath
        Public Gpg key path. This is only supported on Linux.

    .Example
        $Cert = Get-ChildItem -Path Cert:/CurrentUser/AuthRoot -Recurse | Where-Object {($_.Thumbprint -eq "0563b8630d62d75abbc8ab1e4bdfb5a899b65d43") }
        Protect-GuestConfigurationPackage -Path ./custom_policy/WindowsTLS.zip -Certificate $Cert

    .OUTPUTS
        Return name and path of the signed Guest Configuration Policy package.
#>

function Protect-GuestConfigurationPackage
{
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Certificate")]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "GpgKeys")]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path,

        [Parameter(Mandatory = $true, ParameterSetName = "Certificate")]
        [ValidateNotNullOrEmpty()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [Parameter(Mandatory = $true, ParameterSetName = "GpgKeys")]
        [ValidateNotNullOrEmpty()]
        [string]
        $PrivateGpgKeyPath,

        [Parameter(Mandatory = $true, ParameterSetName = "GpgKeys")]
        [ValidateNotNullOrEmpty()]
        [string]
        $PublicGpgKeyPath
    )

    $Path = Resolve-Path $Path
    if (-not (Test-Path $Path -PathType Leaf))
    {
        throw 'Invalid Guest Configuration package path.'
    }

    try
    {
        $packageFileName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
        $signedPackageFilePath = Join-Path (Get-ChildItem $Path).Directory "$($packageFileName)_signed.zip"
        $tempDir = Join-Path -Path (Get-ChildItem $Path).Directory -ChildPath 'temp'
        Remove-Item $signedPackageFilePath -Force -ErrorAction SilentlyContinue
        $null = New-Item -ItemType Directory -Force -Path $tempDir

        # Unzip policy package.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($Path, $tempDir)

        # Get policy name
        $dscDocument = Get-ChildItem -Path $tempDir -Filter *.mof
        if (-not $dscDocument)
        {
            throw "Invalid policy package, failed to find dsc document in policy package."
        }

        $policyName = [System.IO.Path]::GetFileNameWithoutExtension($dscDocument)

        $osPlatform = Get-OSPlatform
        if ($PSCmdlet.ParameterSetName -eq "Certificate")
        {
            if ($osPlatform -eq "Linux")
            {
                throw 'Certificate signing not supported on Linux.'
            }

            # Create catalog file
            $catalogFilePath = Join-Path -Path $tempDir -ChildPath "$policyName.cat"
            Remove-Item $catalogFilePath -Force -ErrorAction SilentlyContinue
            Write-Verbose "Creating catalog file : $catalogFilePath."
            New-FileCatalog -Path $tempDir -CatalogVersion 2.0 -CatalogFilePath $catalogFilePath | Out-Null

            # Sign catalog file
            Write-Verbose "Signing catalog file : $catalogFilePath."
            $CodeSignOutput = Set-AuthenticodeSignature -Certificate $Certificate -FilePath $catalogFilePath

            $Signature = Get-AuthenticodeSignature $catalogFilePath
            if ($null -ne $Signature.SignerCertificate)
            {
                if ($Signature.SignerCertificate.Thumbprint -ne $Certificate.Thumbprint)
                {
                    throw $CodeSignOutput.StatusMessage
                }
            }
            else
            {
                throw $CodeSignOutput.StatusMessage
            }
        }
        else
        {
            if ($osPlatform -eq "Windows")
            {
                throw 'Gpg signing not supported on Windows.'
            }

            $PrivateGpgKeyPath = Resolve-Path $PrivateGpgKeyPath
            $PublicGpgKeyPath = Resolve-Path $PublicGpgKeyPath
            $ascFilePath = Join-Path $tempDir "$policyName.asc"
            $hashFilePath = Join-Path $tempDir "$policyName.sha256sums"

            Remove-Item $ascFilePath -Force -ErrorAction SilentlyContinue
            Remove-Item $hashFilePath -Force -ErrorAction SilentlyContinue

            Write-Verbose "Creating file hash : $hashFilePath."
            Push-Location -Path $tempDir
            bash -c "find ./ -type f -print0 | xargs -0 sha256sum | grep -v sha256sums > $hashFilePath"
            Pop-Location

            Write-Verbose "Signing file hash : $hashFilePath."
            gpg --import $PrivateGpgKeyPath
            gpg --no-default-keyring --keyring $PublicGpgKeyPath --output $ascFilePath --armor --detach-sign $hashFilePath
        }

        # Zip the signed Guest Configuration package
        Write-Verbose "Creating signed Guest Configuration package : '$signedPackageFilePath'."
        [System.IO.Compression.ZipFile]::CreateFromDirectory($tempDir, $signedPackageFilePath)

        $result = [pscustomobject]@{
            Name = $policyName
            Path = $signedPackageFilePath
        }

        return $result
    }
    finally
    {
        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#EndRegion './Public/Protect-GuestConfigurationPackage.ps1' 151
#Region './Public/Publish-GuestConfigurationPackage.ps1' 0

<#
    .SYNOPSIS
        Publish a Guest Configuration policy package to Azure blob storage.
        The goal is to simplify the number of steps by scoping to a specific
        task.

        Generates a SAS token with a 3-year lifespan, to mitigate the risk
        of a malicious person discovering the published content.

        Requires a resource group, storage account, and container
        to be pre-staged. For details on how to pre-stage these things see the
        documentation for the Az Storage cmdlets.
        https://docs.microsoft.com/en-us/azure/storage/blobs/storage-quickstart-blobs-powershell.

    .Parameter Path
        Location of the .zip file containing the Guest Configuration artifacts

    .Parameter ResourceGroupName
        The Azure resource group for the storage account

    .Parameter StorageAccountName
        The name of the storage account for where the package will be published
        Storage account names must be globally unique

    .Parameter StorageContainerName
        Name of the storage container in Azure Storage account (default: "guestconfiguration")

    .Example
        Publish-GuestConfigurationPackage -Path ./package.zip -ResourceGroupName 'resourcegroup' -StorageAccountName 'sa12345'

    .OUTPUTS
        Return a publicly accessible URI containing a SAS token with a 3-year expiration.
#>

function Publish-GuestConfigurationPackage
{
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Path,

        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ResourceGroupName,

        [Parameter(Position = 2, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $StorageAccountName,

        [Parameter()]
        [System.String]
        $StorageContainerName = 'guestconfiguration',

        [Parameter()]
        [System.Management.Automation.SwitchParameter]
        $Force
    )

    # Get Storage Context
    $Context = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName |
        ForEach-Object { $_.Context }

    # Blob name from file name
    $BlobName = (Get-Item -Path $Path -ErrorAction Stop).Name

    $setAzStorageBlobContentParams = @{
        Context   = $Context
        Container = $StorageContainerName
        Blob      = $BlobName
        File      = $Path
    }

    if ($true -eq $Force)
    {
        $setAzStorageBlobContentParams.Add('Force', $true)
    }

    # Upload file
    $null = Set-AzStorageBlobContent @setAzStorageBlobContentParams

    # Get url with SAS token
    # THREE YEAR EXPIRATION
    $StartTime = Get-Date

    $newAzStorageBlobSASTokenParams = @{
        Context    = $Context
        Container  = $StorageContainerName
        Blob       = $BlobName
        StartTime  = $StartTime
        ExpiryTime = $StartTime.AddYears('3')
        Permission = 'rl'
        FullUri    = $true
    }

    $SAS = New-AzStorageBlobSASToken @newAzStorageBlobSASTokenParams

    # Output
    return [PSCustomObject]@{
        ContentUri = $SAS
    }
}
#EndRegion './Public/Publish-GuestConfigurationPackage.ps1' 107
#Region './Public/Publish-GuestConfigurationPolicy.ps1' 0

<#
    .SYNOPSIS
        Publishes the Guest Configuration policy in Azure Policy Center.

    .Parameter Path
        Guest Configuration policy path.

    .Example
        Publish-GuestConfigurationPolicy -Path ./git/custom_policy
#>

function Publish-GuestConfigurationPolicy
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Path,

        [Parameter()]
        [System.String]
        $ManagementGroupName
    )

    $rmContext = Get-AzContext
    Write-Verbose -Message "Publishing Guest Configuration policy using '$($rmContext.Name)' AzContext."

    # Publish policies
    $currentFiles = @(Get-ChildItem $Path | Where-Object -FilterScript {
        $_.name -like "DeployIfNotExists.json" -or $_.name -like "AuditIfNotExists.json"
    })

    if ($currentFiles.Count -eq 0)
    {
        throw "No valid AuditIfNotExists.json or DeployIfNotExists.json files found at $Path"
    }
    elseif ($currentFiles.Count -gt 1)
    {
        throw "More than one valid json found at $Path"
    }

    $policyFile = $currentFiles[0]
    $jsonDefinition = Get-Content -Path $policyFile | ConvertFrom-Json | ForEach-Object { $_ }
    $definitionContent = $jsonDefinition.Properties

    $newAzureRmPolicyDefinitionParameters = @{
        Name        = $jsonDefinition.name
        DisplayName = $($definitionContent.DisplayName | ConvertTo-Json -Depth 20).replace('"', '')
        Description = $($definitionContent.Description | ConvertTo-Json -Depth 20).replace('"', '')
        Policy      = $($definitionContent.policyRule | ConvertTo-Json -Depth 20)
        Metadata    = $($definitionContent.Metadata | ConvertTo-Json -Depth 20)
        ApiVersion  = '2018-05-01'
        Verbose     = $true
    }

    if ($definitionContent.PSObject.Properties.Name -contains 'parameters')
    {
        $newAzureRmPolicyDefinitionParameters['Parameter'] = ConvertTo-Json -InputObject $definitionContent.parameters -Depth 15
    }

    if ($ManagementGroupName)
    {
        $newAzureRmPolicyDefinitionParameters['ManagementGroupName'] = $ManagementGroupName
    }

    Write-Verbose -Message "Publishing '$($jsonDefinition.properties.displayName)' ..."
    New-AzPolicyDefinition @newAzureRmPolicyDefinitionParameters
}
#EndRegion './Public/Publish-GuestConfigurationPolicy.ps1' 71
#Region './Public/Start-GuestConfigurationPackageRemediation.ps1' 0

<#
    .SYNOPSIS
        Starting to remediate a Guest Configuration policy package.

    .Parameter Path
        Relative/Absolute local path of the zipped Guest Configuration package.

    .Parameter Parameter
        Policy parameters.

    .Parameter Force
        Allows cmdlet to make changes on machine for remediation that cannot otherwise be changed.

    .Example
        Start-GuestConfigurationPackage -Path ./custom_policy/WindowsTLS.zip -Force

        $Parameter = @(
            @{
                ResourceType = "MyFile"            # dsc configuration resource type (mandatory)
                ResourceId = 'hi'       # dsc configuration resource property id (mandatory)
                ResourcePropertyName = "Ensure"       # dsc configuration resource property name (mandatory)
                ResourcePropertyValue = 'Present'     # dsc configuration resource property value (mandatory)
            })

        Start-GuestConfigurationPackage -Path ./custom_policy/AuditWindowsService.zip -Parameter $Parameter -Force

    .OUTPUTS
        None.
#>

function Start-GuestConfigurationPackageRemediation
{
    [CmdletBinding()]
    [OutputType()]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path,

        [Parameter()]
        [Switch]
        $Force,

        [Parameter()]
        [Hashtable[]]
        $Parameter = @()
    )

    $osPlatform = Get-OSPlatform

    if ($osPlatform -eq 'MacOS')
    {
        throw 'The Install-GuestConfigurationPackage cmdlet is not supported on MacOS'
    }

    $verbose = ($PSBoundParameters.ContainsKey('Verbose') -and ($PSBoundParameters['Verbose'] -eq $true))
    $systemPSModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', 'Process')
    if ($PSBoundParameters.ContainsKey('Force') -and $Force)
    {
        $withForce = $true
    }
    else
    {
        $withForce = $false
    }

    try
    {
        # Install the package
        $packagePath = Install-GuestConfigurationPackage -Path $Path -Force:$withForce -ErrorAction 'Stop'

        # The leaf part of the Path returned by Install-GCPackage will always be the BaseName of the MOF.
        $packageName = Get-GuestConfigurationPackageName -Path $packagePath

        # Confirm mof exists
        $packageMof = Join-Path -Path $packagePath -ChildPath "$packageName.mof"
        $dscDocument = Get-Item -Path $packageMof -ErrorAction 'SilentlyContinue'
        if (-not $dscDocument)
        {
            throw "Invalid Guest Configuration package, failed to find dsc document at $packageMof path."
        }

        # Throw if package is not set to AuditAndSet. If metaconfig is not found, assume Audit.
        $metaConfig = Get-GuestConfigurationPackageMetaConfig -Path $packagePath
        if ($metaConfig.Type -ne "AuditAndSet")
        {
            throw "Cannot run Start-GuestConfigurationPackage on a package that is not set to AuditAndSet. Current metaconfig contents: $metaconfig"
        }

        # Update mof values
        if ($Parameter.Count -gt 0)
        {
            Write-Debug -Message "Updating MOF with $($Parameter.Count) parameters."
            Update-MofDocumentParameters -Path $dscDocument.FullName -Parameter $Parameter
        }

        Write-Verbose -Message "Publishing policy package '$packageName' from '$packagePath'."
        Publish-DscConfiguration -ConfigurationName $packageName -Path $packagePath -Verbose:$verbose

        # Set LCM settings to force load powershell module.
        $metaConfigPath = Join-Path -Path $packagePath -ChildPath "$packageName.metaconfig.json"
        Write-Debug -Message "Setting 'LCM' Debug mode to force module import."
        Update-GuestConfigurationPackageMetaconfig -metaConfigPath $metaConfigPath -Key 'debugMode' -Value 'ForceModuleImport'
        Write-Debug -Message "Setting 'LCM' configuration mode to ApplyAndMonitor."
        Update-GuestConfigurationPackageMetaconfig -metaConfigPath $metaConfigPath -Key 'configurationMode' -Value 'ApplyAndMonitor'
        Set-DscLocalConfigurationManager -ConfigurationName $packageName -Path $packagePath -Verbose:$verbose

        # Run Deploy/Remediation
        Start-DscConfiguration -ConfigurationName $packageName -Verbose:$verbose
    }
    finally
    {
        $env:PSModulePath = $systemPSModulePath
    }
}
#EndRegion './Public/Start-GuestConfigurationPackageRemediation.ps1' 119
#Region './Public/Test-GuestConfigurationPackage.ps1' 0

<#
    .SYNOPSIS
        Tests a Guest Configuration policy package.

    .Parameter Path
        Full path of the zipped Guest Configuration package.

    .Parameter Parameter
        Policy parameters.

    .Example
        Test-GuestConfigurationPackage -Path ./custom_policy/WindowsTLS.zip

        $Parameter = @(
            @{
                ResourceType = "Service"            # dsc configuration resource type (mandatory)
                ResourceId = 'windowsService'       # dsc configuration resource property id (mandatory)
                ResourcePropertyName = "Name"       # dsc configuration resource property name (mandatory)
                ResourcePropertyValue = 'winrm'     # dsc configuration resource property value (mandatory)
            })

        Test-GuestConfigurationPackage -Path ./custom_policy/AuditWindowsService.zip -Parameter $Parameter

    .OUTPUTS
        Returns compliance details.
#>

function Test-GuestConfigurationPackage
{
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path,

        [Parameter()]
        [Hashtable[]]
        $Parameter = @(),

        [Parameter()]
        [Switch]
        $Force
    )

    if ($IsMacOS)
    {
        throw 'The Test-GuestConfigurationPackage cmdlet is not supported on MacOS'
    }

    # Determine if verbose is enabled to pass down to other functions
    $verbose = ($PSBoundParameters.ContainsKey("Verbose") -and ($PSBoundParameters["Verbose"] -eq $true))
    $systemPSModulePath = [Environment]::GetEnvironmentVariable("PSModulePath", "Process")
    $gcBinPath = Get-GuestConfigBinaryPath
    $guestConfigurationPolicyPath = Get-GuestConfigPolicyPath
    if ($PSBoundParameters.ContainsKey('Force') -and $PSBoundParameters['Force'])
    {
        $withForce = $true
    }
    else
    {
        $withForce = $false
    }

    try
    {
        # Get the installed policy path, and install if missing
        $packagePath = Install-GuestConfigurationPackage -Path $Path -Verbose:$verbose -Force:$withForce


        $packageName = Get-GuestConfigurationPackageName -Path $packagePath
        Write-Debug -Message "PackageName: '$packageName'."
        # Confirm mof exists
        $packageMof = Join-Path -Path $packagePath -ChildPath "$packageName.mof"
        $dscDocument = Get-Item -Path $packageMof -ErrorAction 'SilentlyContinue'
        if (-not $dscDocument)
        {
            throw "Invalid Guest Configuration package, failed to find dsc document at '$packageMof' path."
        }

        # update configuration parameters
        if ($Parameter.Count -gt 0)
        {
            Write-Debug -Message "Updating MOF with $($Parameter.Count) parameters."
            Update-MofDocumentParameters -Path $dscDocument.FullName -Parameter $Parameter
        }

        Write-Verbose -Message "Publishing policy package '$packageName' from '$packagePath'."
        Publish-DscConfiguration -ConfigurationName $packageName -Path $packagePath -Verbose:$verbose

        # Set LCM settings to force load powershell module.
        Write-Debug -Message "Setting 'LCM' Debug mode to force module import."
        $metaConfigPath = Join-Path -Path $packagePath -ChildPath "$packageName.metaconfig.json"
        Update-GuestConfigurationPackageMetaconfig -metaConfigPath $metaConfigPath -Key 'debugMode' -Value 'ForceModuleImport'
        Set-DscLocalConfigurationManager -ConfigurationName $packageName -Path $packagePath -Verbose:$verbose

        $inspecProfilePath = Get-InspecProfilePath
        Write-Debug -Message "Clearing Inspec profiles at '$inspecProfilePath'."
        Remove-Item -Path $inspecProfilePath -Recurse -Force -ErrorAction SilentlyContinue

        Write-Verbose -Message "Getting Configuration resources status."
        $getResult = @()
        $getResult = $getResult + (Get-DscConfiguration -ConfigurationName $packageName -Verbose:$verbose)
        return $getResult
    }
    finally
    {
        $env:PSModulePath = $systemPSModulePath
    }
}
#EndRegion './Public/Test-GuestConfigurationPackage.ps1' 113


# SIG # Begin signature block
# MIIjlgYJKoZIhvcNAQcCoIIjhzCCI4MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAXIrOmDnWZH12k
# rFfDFTbr//LyLk/N7/Fj3CpqLBY8jaCCDYUwggYDMIID66ADAgECAhMzAAAB4HFz
# JMpcmPgZAAAAAAHgMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ2WhcNMjExMjAyMjEzMTQ2WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDRXpc9eiGRI/2BlmU7OMiQPTKpNlluodjT2rltPO/Gk47bH4gBShPMD4BX/4sg
# NvvBun6ZOG2dxUW30myWoUJJ0iRbTAv2JFzjSpVQvPE+D5vtmdu6WlOR2ahF4leF
# 5Vvk4lPg2ZFrqg5LNwT9gjwuYgmih+G2KwT8NMWusBhO649F4Ku6B6QgA+vZld5S
# G2XWIdvS0pmpmn/HFrV4eYTsl9HYgjn/bPsAlfWolLlEXYTaCljK7q7bQHDBrzlR
# ukyyryFpPOR9Wx1cxFJ6KBqg2jlJpzxjN3udNJPOqarnQIVgB8DUm3I5g2v5xTHK
# Ovz9ucN21467cYcIxjPC4UkDAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUVBWIZHrG4UIX3uX4142l+8GsPXAw
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzQ2MzAxMDAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AE5msNzmYzYbNgpnhya6YsrM+CIC8CXDu10nwzZtkgQciPOOqAYmFcWJCwD5VZzs
# qFwad8XIOrfCylWf4hzn09mD87yuazpuCstLSqfDLNd3740+254vEZqdGxOglAGU
# ih2IiF8S0GDwucpLGzt/OLXPFr/d4MWxPuX0L+HB5lA3Y/CJE673dHGQW2DELdqt
# ohtkhp+oWFn1hNDDZ3LP++HEZvA7sI/o/981Sh4kaGayOp6oEiQuGeCXyfrIC9KX
# eew0UlYX/NHVDqr4ykKkqpHtzbUbuo7qovUHPbYKcRGWrrEtBS5SPLFPumqsRtzb
# LgU9HqfRAN36bMsd2qynGyWBVFOM7NMs2lTCGM85Z/Fdzv/8tnYT36Cmbue+IM+6
# kS86j6Ztmx0VIFWbOvNsASPT6yrmYiecJiP6H0TrYXQK5B3jE8s53l+t61ab0Eul
# 7DAxNWX3lAiUlzKs3qZYQEK1LFvgbdTXtBRnHgBdABALK3RPrieIYqPln9sAmg3/
# zJZi4C/c2cWGF6WwK/w1Nzw08pj7jaaZZVBpCeDe+y7oM26QIXxracot7zJ21/TL
# 70biK36YybSUDkjhQPP/uxT0yebLNBKk7g8V98Wna2MsHWwk0sgqpkjIp02TrkVz
# 26tcF2rml2THRSDrwpBa4x9c8rM8Qomiyeh2tEJnsx2LMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCFWcwghVjAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAAHgcXMkylyY+BkAAAAA
# AeAwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGhT
# TetgOELCrFFg/XIDo96Gt1ditdlkkDIThOdxN6wKMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAKiI7AKfE11QUuuMuhZhYRuv/YCwrRp7f3vhp
# AESqonZN8NddZEBLG3A0pqZkxxgYptyO+ExsUsfprhcdqPD4WciU7Da4OsjbWSKQ
# hqMlIH/iruzmmYK9uejhlV/G2MzfKdG0jF1zSaNuDS2XmAMuf4E4Lnt7WgmgRfLK
# N7B5TfllBP2zeRyipMe8e7JTmW2CyvktVAU7/N8P9THZbaGK1DaiRVjvjIBKEoDt
# SCh3qIaFTTHB894GDeaPXt2rFMzCXiZKEWMAC7LSPRUsqu+SOngVo+F+WmeYY/VL
# 3YmW1e2/a0AbJKq6SyzSvpZhQvJeKblpJMP5EysVQudKhvzK+KGCEvEwghLtBgor
# BgEEAYI3AwMBMYIS3TCCEtkGCSqGSIb3DQEHAqCCEsowghLGAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFVBgsqhkiG9w0BCRABBKCCAUQEggFAMIIBPAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCByr+7B/tOh16/2/ktsdoxgV3hTYOayB4i/
# sxElfcfFCwIGYYHZDlPoGBMyMDIxMTEwODE4MjY0MC4xNDlaMASAAgH0oIHUpIHR
# MIHOMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQL
# EyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046RjdBNi1FMjUxLTE1MEExJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2Wggg5EMIIE9TCCA92gAwIBAgITMwAAAVmf/H5fLOry
# QwAAAAABWTANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDAeFw0yMTAxMTQxOTAyMTVaFw0yMjA0MTExOTAyMTVaMIHOMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQg
# T3BlcmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046
# RjdBNi1FMjUxLTE1MEExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNl
# cnZpY2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCueMRhyWfEh0RL
# TSKAaPQBujK6PIBGQrfFoFf5jXSLdrTDj981WFOPrEbCJsU8H8yRAwVmk3Oy8ZRM
# v9d9Nn0Znf0dqcJ2O6ck/dMr2QJkEC2eg/n2hgcMIYua63v7ZgSXWwFxWfKi9iQ3
# OLcQZ99DK9QvAxQXayI8Gz/otkXQDmksCLP8ULDHmQM97+Y/VRHcKvPojOmHC3Ki
# q2AMD/jhOfN+9Uk+ZI9n+6rk6Hk14Urw3MymK1aJC92Z9PijQJ26aeKx9bV8ppoF
# 0HIFQs9RPxMvDRLL2dRY1eUD+qLwzE/GAKOys2mL0+CMfsTFb1vtf9TJ2GmqEfGy
# 50MZk2TjAgMBAAGjggEbMIIBFzAdBgNVHQ4EFgQU9tCphUa8rfrk6yfXiMI8suk3
# Y+cwHwYDVR0jBBgwFoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBL
# oEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMv
# TWljVGltU3RhUENBXzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggr
# BgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNU
# aW1TdGFQQ0FfMjAxMC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAK
# BggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOCAQEAjZFUEugPgYa3xjggFqNynLlG
# uHrLac8p/mS5ZIdKSZgCaeBFA6y1rInmAn9qMqHPCo1TAvjRxRVbxy60jIVp0eRb
# WOpd2elK/SEwUs+uI+cE0URPLyKUIh1WI0VTTxkdrYqhuZyj+frA9K2SOOuDhTc+
# J+3qwyTqVeyJtS/7AMH1/hh6HOI+a37gLkExWPNrHWL7RzOC08cFffe7oZRbOdqB
# 2qXRVtSl7erzMRF50l/LKEH1HfjPmKtye7nXOkfeNRrsX3egNL3nFeeiY75qQp4O
# I0ZKrgHsn/3SpkFGkdXyrwCwUQJmZAFLVoo0v9zJHkL/5VLx1aOxjxcyfzt8CTCC
# BnEwggRZoAMCAQICCmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29m
# dCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1
# NVoXDTI1MDcwMTIxNDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAw
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/
# aZRrdFQQ1aUKAIKF++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxh
# MFmxMEQP8WCIhFRDDNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhH
# hjKEHnRhZ5FfgVSxz5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tk
# iVBisV39dx898Fd1rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox
# 8NpOBpG2iAg16HgcsOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJN
# AgMBAAGjggHmMIIB4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIox
# kPNDe3xGG8UzaFqFbVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0P
# BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9
# lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQu
# Y29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3Js
# MFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAG
# A1UdIAEB/wSBlTCBkjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAG
# CCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEA
# dABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXED
# PZ2joSFvs+umzPUxvs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgr
# UYJEEvu5U4zM9GASinbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c
# 8pl5SpFSAK84Dxf1L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFw
# nzJKJ/1Vry/+tuWOM7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFt
# w5yjojz6f32WapB4pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk
# 7Pf0v35jWSUPei45V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9d
# dJgiCGHasFAeb73x4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zG
# y9iCtHLNHfS4hQEegPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3
# yKxO2ii4sanblrKnQqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7c
# RDyXUHHXodLFVeNp3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wkn
# HNWzfjUeCLraNtvTX4/edIhJEqGCAtIwggI7AgEBMIH8oYHUpIHRMIHOMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3Nv
# ZnQgT3BlcmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RjdBNi1FMjUxLTE1MEExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVACp2ywCPH4TufEglq6WZ171xGbIRoIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDlM5etMCIYDzIwMjExMTA4MTYzMzQ5WhgPMjAyMTExMDkxNjMzNDlaMHcw
# PQYKKwYBBAGEWQoEATEvMC0wCgIFAOUzl60CAQAwCgIBAAICJQQCAf8wBwIBAAIC
# EX4wCgIFAOU06S0CAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAK
# MAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQA4s65m53e6
# 86V4XVBzVK+si5pP/0KqXFq5K1d7wN1dhJTgt5jBY/KmehKAD8FAVMOIEh5hrQtK
# rQcuM0pyGF7J5r8GfvX8Hht+sYx89FE09zvnKzKe3wX/PlnKQJbqsa4+SUc0SJqb
# LJRDFWyoK8pkEjg7zs74qNlsJPONOR8j6TGCAw0wggMJAgEBMIGTMHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABWZ/8fl8s6vJDAAAAAAFZMA0GCWCG
# SAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZI
# hvcNAQkEMSIEIF8g0xyQvKsfQ9EjAzgu5TVbASWKLxWUUF9GGetTckHFMIH6Bgsq
# hkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgAVgbz78w5nzXks5iU+PnRgPro/6qu/3y
# pFJ9+q8TQ+gwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAIT
# MwAAAVmf/H5fLOryQwAAAAABWTAiBCDSJwc4AdOK0S4osTNh1NGiFwwcatz0ZQEr
# 9XP86mKzhjANBgkqhkiG9w0BAQsFAASCAQBccy/2zGaXlXLOOBjlckVFqR891ck1
# tGvyUvEug28zcBv0h4eI6pb1qOw3qri+fuktnSbqTTwid1l6vsuxzx8RZTaqAEbS
# StCCsx/VNqerGVNXVodQNbMzz9GYzgmlGkhKy5Grwb15HvLIgZMUEhKuxWD88Mzk
# 68rNANNM2YDXnFWDnzt1W8XSjsunZ2DnopLLBbaQW4ySY55gybWZppPM2dMeyBYK
# m4o/zsFQEAWYCMB0q4XBPCwkP0HXgvs2iQLqi9fTrx3A1U2n1UBXojldag56/9M9
# nZFXdqff2v76DxRhyXpHyprcXJNOiVKDcmMsuuS7rP8csZD/gUBnZNX3
# SIG # End signature block
