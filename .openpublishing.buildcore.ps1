<#
.SYNOPSIS
    This is a Powershell script to create a build
.DESCRIPTION
    Usage: Run .openpublishing.build.ps1 -parameters:"_op_accessToken=<your Git repository access token>"
    Refer to https://opsdocs.azurewebsites.net/en-us/opsdocs/partnerdocs/local-build-and-preview?branch=master for more information.
.PARAMETER parameters
    Specifies optional paramerters.
    _op_accessToken: access token for your Git repository, optional if the repository is public.
    buildConfigFile: build config file for local build.
    forceDownload: force download filemaps
#>

param(
    [string]$parameters
)

# Use TLS 1.2 for Powershell.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

trap
{
    # Handle the error
    $err = $_.Exception
    Write-Error "Exception occurred. $err.Message" -ErrorAction Continue

    while($err.InnerException) {
        $err = $err.InnerException
        Write-Error "Inner exception: $err.Message" -ErrorAction Continue
    };

    # End the script.
    exit 1
}

# Main
$errorActionPreference = 'Stop'

$contextDictionary = @{}
$currentDictionary = @{
    environment = @{};
    docset = @{};
    context = @{}
}

# Entry-point package
$entryPointPackage = @{
    id = "opbuild.scripts";
    version = "latest";
    targetFramework = "net45";
}

# local build config parser package
$localBuildConfigParserPackage = @{
    id = "opbuild.prepareConfigForLocalBuild";
    version = "latest";
    targetFramework = "net45";
}

# Pre-step: Set the repository root folder, working folder, packages folder and last op script version file path
$source = $($MyInvocation.MyCommand.Definition)
$repositoryRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$workingDirectory = "$repositoryRoot\.optemp"
$packagesDirectory = "$workingDirectory\packages"
$lastOpScriptVersionRecordFile = "$workingDirectory\lastOpScriptVersion.txt";
$localBuildResourceFolder = "$workingDirectory\localbuild"
$localBuildPackagesDirectory = "$localBuildResourceFolder\packages"

Filter timestamp
{
    if (![string]::IsNullOrEmpty($_) -and ![string]::IsNullOrWhiteSpace($_))
    {
        Write-Host -NoNewline -ForegroundColor Magenta "[$(((get-date).ToUniversalTime()).ToString("yyyy-MM-dd HH:mm:ss.ffffffZ"))]: "
    }

    $_
}

echo "Running build core ps1 with parameters: $parameters" | timestamp

# Print current PowerShell environment version
echo "Current PowerShell environment version: $($PSVersionTable.PSVersion.ToString())" | timestamp

# Check PowerShell version, exit when below 4.0
if ($PSVersionTable.PSVersion.Major -lt 4)
{
    Write-Error "PowerShell version should be equal with or higher than 4.0, current PowerShell version is $PSVersionTable.PSVersion.Major"
}

# Define system value
$systemDefaultVariables = @{
    AzureLocalizedRepositoryUrlFormat = "(?i)(https://(.*)?github.com/MicrosoftDocs/azure-docs-pr\.(.+\-.+)(\.git)?)|(https://(.*)?github.com/wacn/mc-docs-pr\.(.+\-.+)(\.git)?)"
    ResourceContainerUrl = "https://opbuildstorageprod.blob.core.windows.net/opps1container";
    DefaultEntryPoint = "op";
    UpdateNugetExe = $false;
    UpdateNugetConfig = $true;
    UpdateMdproj = $true;
    NeedBuildMdproj = $true;
    MdprojTargets = "build";
    OutputFolder = "$repositoryRoot\_site";
    LogOutputFolder = "$repositoryRoot\log";
    CacheFolder = "$workingDirectory\cache";
    LogLevel = "Info";
    NeedGeneratePdf = $false;
    NeedGenerateIntellisense = $false;
    UpdatePackagesConfig = $true;
    GlobalMetadataFile = "";
    StepProgressInfoFile = "";
    EnvironmentResourcesFile = "";
    DefaultMaxRetryCount = 3;
    NeedFetchSubmodule = $true;
    DefaultSubmoduleBranch = "master";
    DownloadNugetExeTimeOutInSeconds= 300;
    DownloadNugetConfigTimeOutInSeconds= 30;
    GitCloneRepositoryTimeOutInSeconds = 600;
    GitPullRepositoryTimeOutInSeconds = 300;
    GitOtherOperationsTimeOutInSeconds = 60;
    BuildToolParallelism = 0;
    AllowUseDynamicRendering = $false;
    IsDynamicRendering = $false;
    PreservedFallbackFolderRegex = "(?i)_repo\.(.+-.+)";
    PreservedFallbackCopyFileSearchPattern = "toc.md,toc.yml";
    PreservedTemplateFolders = @("_themes", "_themes.MSDN.Modern", "_themes.MSDN.PartnerCenter", "_themes.VS.Modern", "_themes.VS.UHF", "_themes.TechNet.Modern", "_themes.OPS", "_themes.pdf");
    PreservedContentTypeMapping = @{
      Conceptual = "Content";
      ManagedReference = "Content";
      RestApi = "Content";
      AzureCli = "Content";
      AzurePyCli = "Content";
      AzureXplatCli = "Content";
      JavaScriptReference = "Content";
      YamlDocument = "Content";
      Hub = "Content";
      Landing = "Content";
      GuideLanding = "Content";
      GuideStep = "Content";
      Hub2 = "Content";
      LandingData = "Content";
      RESTOperation = "Content";
      RESTOperationGroup = "Content";
      Tutorial = "Content";
      TOC = "TOC";
      ContextObject = "TOC";
      Resource = "Resource"
    };
    DefaultErrorLogCodesString = "InvalidInclude,InvalidCodeSnippet,InvalidInlineCodeSnippet";
    DefaultWarningLogCodesString = "";
    DefaultInfoLogCodesString = "";
    DefaultIntellisenseErrorLogCodes = "";
    DefaultIntellisenseWarningLogCodes = "";
    DefaultIntellisenseInfoLogCodes = "DuplicateUids";
    EnableBuildToolDebugModel = $true;
    EnableFileMapGenerator = $true;
    EnableXrefmapResolver = $true;
    EnableFallbackPlugin = $true;
    EnableIncrementalBuild = $true;
    EnableIncrementalPostProcessing = $true;
    EnableGitFeatures = $true;
    EnableCustomValidation = $true;
    ResolveUserProfile = $false;
    ResolveUserProfileByAccessToken = $true;
    AbandonGitUserProfileLocalCache = $true;
    ResolveUserProfileUsingGitHub = $true;
    ContributionBranch = "";
    UseTemplateWithCachedCommitId = $false;
    PdfTemplateFolder = "";
    NeedGeneratePdfExternalLink = $true;
    EnablePdfHeaderFooter = $false;
    ForceInitialize = $false;
    PdfConvertParallelism = 4;
    ReplayErrorWarningLogs = $true;
    EnableMasterRedirectionFile = $true;
    NormalizeContentInBuildTool = $false;
    TocChangeTriggerFullBuild = $false;
    UserSpecifiedChangeListTsvFilePath = $null;
    UserSpecifiedDependentListFilePath = $null;
    FullDependentListFilePath = $null;
    MinimumCommonPackageVersion = "1.63.0";
    MinimumEntryPointPackageVersion = "1.63.0";
    IsServerBuild = $false;
    BuildType = $null;
    SkipDereferenceForPR = $false;
    CopyFileFromFallbackFolders = $true;
    CopyFileSearchPatternForGeneratePdf = "*.jpg,*.png,*.svg,*.jpeg,*.gif";
    NonPublishedCopyFileSearchPattern = $null;
    PreservedXrefServiceEndpointByEnvironment = @{
        Production = "https://xref.docs.microsoft.com"
        NonProduction = "https://xrefppe.docs.microsoft.com"
    };
    UseDocfxV3 = $false
}

$systemDefaultTargets = @{
    build = @{
        NeedInit = $true;
        NeedBuild = $true;
        NeedServe = $false;
        NeedGenerateIntellisense = $false;
        NeedGeneratePdf = $false;
        NeedBuildTheme = $false;
        NeedSync = $false;
        NeedResolveXrefmap = $true;
    };
    init = @{
        NeedInit = $true;
        NeedBuild = $false;
        NeedServe = $false;
        NeedGenerateIntellisense = $false;
        NeedBuildTheme = $false;
        NeedGeneratePdf = $false;
    };
    localbuild = @{
        NeedInit = $false;
        NeedBuild = $true;
        NeedServe = $false;
        NeedGenerateIntellisense = $false;
        NeedBuildTheme = $false;
        NeedSync = $false;
        NeedGeneratePdf = $false;
    };
    serve = @{
        NeedInit = $true;
        NeedBuild = $true;
        NeedServe = $true;
        NeedGenerateIntellisense = $false;
        NeedBuildTheme = $false;
        NeedSync = $false;
        NeedGeneratePdf = $false;
    };
    generateIntellisense = @{
        NeedInit = $true;
        NeedBuild = $false;
        NeedServe = $false;
        NeedGenerateIntellisense = $true;
        NeedBuildTheme = $false;
        NeedSync = $false;
        NeedGeneratePdf = $false;
    };
    generatePdf = @{
        NeedInit = $true;
        NeedBuild = $true;
        NeedServe = $false;
        NeedGenerateIntellisense = $false;
        NeedBuildTheme = $false;
        NeedSync = $false;
        NeedGeneratePdf = $true;
    };
    sync = @{
        NeedInit = $true;
        NeedBuild = $false;
        NeedServe = $false;
        NeedGenerateIntellisense = $false;
        NeedGeneratePdf = $false;
        NeedBuildTheme = $false;
        NeedSync = $true;
        EntryPoint = "reposyncer";
    };
    buildTheme = @{
        NeedInit = $true;
        NeedBuild = $false;
        NeedServe = $false;
        NeedGenerateIntellisense = $false;
        NeedGeneratePdf = $false;
        NeedBuildTheme = $true;
        NeedSync = $false;
        EntryPoint = "template";
    };
}

Function Write-HostWithTimestamp([string]$output)
{
    Write-Host -NoNewline -ForegroundColor Magenta "[$(((get-date).ToUniversalTime()).ToString("HH:mm:ss.ffffffZ"))]: "
    Write-Host $output
}

Function ConsoleErrorAndExit([string]$message, [int]$exitCode)
{
    Write-Host -ForegroundColor Red $message
    return $exitCode
}

Function GetCurrentLine
{
    return $Myinvocation.ScriptlineNumber
}

Function ParseBoolValue([string]$variableName, [string]$stringValue, [bool]$defaultBoolValue)
{
    if([string]::IsNullOrEmpty($stringValue))
    {
        return $defaultBoolValue
    }

    try
    {
        $parsedBoolValue = [System.Convert]::ToBoolean($stringValue)
    }
    catch
    {
        Write-Error "variable $variableName does not have a valid bool value: $stringValue. Exception: $($_.Exception.Message)"
    }

    return $parsedBoolValue
}

Function GetValueFromVariableName([string]$variableValue, [string]$defaultStringValue)
{
    if([string]::IsNullOrEmpty($variableValue))
    {
        $variableValue = $defaultStringValue
    }
    return $variableValue
}

Function ParseParameters([string]$parameters)
{
    if([string]::IsNullOrEmpty($parameters))
    {
        return
    }

    $parameterPortions = $parameters.Split(';')
    foreach ($parameterPortion in $parameterPortions)
    {
        $index = $parameterPortion.IndexOf('=')
        if ($index -ne -1)
        {
            $key = $parameterPortion.SubString(0, $index)
            $value = $parameterPortion.SubString($index + 1)
            Set-Variable -Name $key -Value $value -Scope "Script" -Force
            Write-HostWithTimestamp "Create script scope variable with input $parameterPortion"
        }
        else
        {
            Write-HostWithTimestamp "Invalid variable with input $parameterPortion. Ignore it."
        }
    }
}

Function IsPathExists([string]$path)
{
    return Test-Path $path
}

Function CheckPath([string]$path)
{
    if(!(IsPathExists($path)))
    {
        Write-Error "$path doesn't exist"
    }
}

Function JoinPath([string]$rootPath, [string[]]$childPaths)
{
    $destination = $rootPath

    $childPaths | % {
        $destination = Join-Path $destination -ChildPath $_
    }

    return $destination
}

Function CreateFolderIfNotExists([string]$folder)
{
    if(!(Test-Path "$folder"))
    {
        New-Item "$folder" -ItemType Directory
    }
}

Function RetryCommand
{
    param (
        [Parameter(Mandatory=$true)][string]$command,
        [Parameter(Mandatory=$true)][hashtable]$args,
        [Parameter(Mandatory=$false)][int]$maxRetryCount = $systemDefaultVariables.DefaultMaxRetryCount,
        [Parameter(Mandatory=$false)][ValidateScript({$_ -ge 0})][int]$retryIncrementalIntervalInSeconds = 10
    )

    # Setting ErrorAction to Stop is important. This ensures any errors that occur in the command are 
    # treated as terminating errors, and will be caught by the catch block.
    $args.ErrorAction = "Stop"

    $currentRetryIteration = 1
    $retryIntervalInSeconds = 0

    Write-HostWithTimestamp ("Start to run command [{0}] with args [{1}]." -f $command, $($args | Out-String))
    do{
        try
        {
            Write-HostWithTimestamp "Calling iteration $currentRetryIteration"
            & $command @args

            Write-HostWithTimestamp "Command ['$command'] succeeded at iteration $currentRetryIteration."
            return
        }
        Catch
        {
            Write-HostWithTimestamp "Calling iteration $currentRetryIteration failed, exception: '$($_.Exception.Message)'"
        }

        if ($currentRetryIteration -ne $maxRetryCount)
        {
            $retryIntervalInSeconds += $retryIncrementalIntervalInSeconds
            Write-HostWithTimestamp "Command ['$command'] failed. Retrying in $retryIntervalInSeconds seconds."
            Start-Sleep -Seconds $retryIntervalInSeconds
        }
    } while (++$currentRetryIteration -le $maxRetryCount)

    Write-HostWithTimestamp "Command ['$command'] failed. Maybe the network issues, please retry the build later."
    exit 1
}

Function DownloadFile([string]$source, [string]$destination, [bool]$forceDownload, [int]$timeoutSec = -1)
{
    if($forceDownload -or !(IsPathExists($destination)))
    {
        Write-HostWithTimestamp "Download file to $destination from $source with force: $forceDownload"
        $destinationFolder = Split-Path -Parent $destination
        CreateFolderIfNotExists($destinationFolder)
        if ($timeoutSec -lt 0)
        {
            RetryCommand -Command 'Invoke-WebRequest' -Args @{ Uri = $source; OutFile = $destination; }
        }
        else
        {
            RetryCommand -Command 'Invoke-WebRequest' -Args @{ Uri = $source; OutFile = $destination; TimeoutSec = $timeoutSec }
        }
    }
}

Function FindResource(
    [object[]]$resources,
    [parameter(mandatory=$true)]
    [string]$resourceName,
    [string]$resourceVersion = $null
)
{
    foreach ($resource in $resources)
    {
        if ($resource.Name -eq $resourceName)
        {
            if ([string]::IsNullOrEmpty($resourceVersion) -or ($resource.Version -eq $resourceVersion))
            {
                return $resource
            }
        }
    }

    return $null
}

Function GetPackageLatestVersion([string]$nugetExeDestination, [string]$packageName, [string]$nugetConfigDestination, [int]$maxRetryCount, [bool]$usePrereleasePackage = $false, [object[]]$cachedPackageVersions = $null)
{
    $currentRetryIteration = 0;
    $retryIntervalInSeconds = 0;
    $retryIncrementalIntervalInSeconds = 10;

    do
    {
        Try
        {
            Write-HostWithTimestamp "Use prerelease package for $packageName : $usePrereleasePackage"

            $cachedPackageVersionString = "latest";
            if ($usePrereleasePackage)
            {
                $cachedPackageVersionString = "latest-prerelease"
            }

            $cachedPackageVersion = FindResource($cachedPackageVersions) ($packageName) ($cachedPackageVersionString)
            if ($cachedPackageVersion)
            {
                Write-HostWithTimestamp "Package version for $packageName loaded from cache: $cachedPackageVersion"
                return $cachedPackageVersion.Location
            }

            if ($usePrereleasePackage)
            {
                $filteredPackages = (& "$nugetExeDestination" list $packageName -Prerelease -ConfigFile "$nugetConfigDestination") -split "\n"
            }
            else
            {
                $filteredPackages = (& "$nugetExeDestination" list $packageName -ConfigFile "$nugetConfigDestination") -split "\n"
            }

            if ($LASTEXITCODE -eq 0)
            {
                foreach ($filteredPackage in $filteredPackages)
                {
                    $segments = $filteredPackage -split " "
                    if ($segments.Length -eq 2 -and $segments[0] -eq $packageName)
                    {
                        return $segments[1]
                    }
                }
            }

            Write-HostWithTimestamp "Call iteration '$currentRetryIteration', cannot find latest version for $packageName, filtered packages: $filteredPackages"
        }
        Catch
        {
            Write-HostWithTimestamp "Call iteration '$currentRetryIteration', cannot find latest version for $packageName, exception: $($_.Exception.Message)"
        }

        if ($currentRetryIteration -ne $maxRetryCount)
        {
            $retryIntervalInSeconds += $retryIncrementalIntervalInSeconds
            Write-HostWithTimestamp "List package version failed, sleep $retryIntervalInSeconds seconds..."
            Start-Sleep -Seconds $retryIntervalInSeconds
        }
    } while (++$currentRetryIteration -le $maxRetryCount)

    Write-HostWithTimestamp "Current nuget package list service is busy, please retry the build in 10 minutes"
    exit 1
}

Function RestorePackage([string] $nugetExeDestination, [string]$packagesDestination, [string]$packagesDirectory, [string]$nugetConfigDestination)
{
    Try
    {
        & "$nugetExeDestination" restore "$packagesDestination" -PackagesDirectory "$packagesDirectory" -ConfigFile "$nugetConfigDestination"
        return $LASTEXITCODE -eq 0
    }
    Catch
    {
        return $false;
    }
}

Function GeneratePackagesConfig([string]$outputFilePath, [object[]]$dependencies, [string]$nugetExeDestination, [object[]]$cachedPackageVersions = $null)
{
    $packageConfigXmlTemplate = @'
<?xml version="1.0" encoding="utf-8"?>
<packages></packages>
'@

    $packageConfigXml = [xml]$packageConfigXmlTemplate
    foreach ($dependency in $dependencies)
    {
        $packageNode = $packageConfigXml.CreateElement("package")
        $packageNode.SetAttribute("id", $dependency.id)
        
        if ($dependency.version -eq "latest" -or $dependency.version -eq "latest-prerelease")
        {
            $usePrereleasePackage = $dependency.version -eq "latest-prerelease"

            # Get latest package version
            $dependency.actualVersion = GetPackageLatestVersion($nugetExeDestination) ($dependency.id) ($nugetConfigDestination) ($systemDefaultVariables.DefaultMaxRetryCount) ($usePrereleasePackage) ($cachedPackageVersions)

            Write-HostWithTimestamp "Using version $($dependency.actualVersion) for package $($dependency.id) (requested: $($dependency.version))"
        }
        else
        {
            $dependency.actualVersion = $dependency.version
        }
        $packageNode.SetAttribute("version", $dependency.actualVersion)

        $packageNode.SetAttribute("targetFramework", $dependency.targetFramework)
        $packageConfigXml.SelectSingleNode("packages").AppendChild($packageNode)
    }
    
    if (IsPathExists($outputFilePath))
    {
        Remove-Item $outputFilePath -Force
    }
    $packageConfigXml.Save($outputFilePath)
}

Function GetPackageVersionWithMinimumRequiredVersionCheck([string]$nugetExeDestination, [string]$packageName, [string]$nugetConfigDestination, [int]$maxRetryCount, [string]$requestedVersion, [bool]$allowFallbackToPrereleaseVersion, [string]$minAllowedVersion = $null, [object]$lastRepoStatus = $null, [object[]]$cachedPackageVersions = $null)
{
    $versionsToCheck = @()
    $isReleaseVersionPackage = $requestedVersion -eq "latest"
    $isPrereleaseVersionPackage = $requestedVersion -eq "latest-prerelease"
    if ($isReleaseVersionPackage -or $isPrereleaseVersionPackage)
    {
        if ($lastRepoStatus -and $($lastRepoStatus.$packageName))
        {
            $packageVersion = $($lastRepoStatus.$packageName);
            Write-HostWithTimestamp "Using cached version $packageVersion for package $packageName"
            $versionsToCheck += $packageVersion
        }

        if ($isReleaseVersionPackage)
        {
            Write-HostWithTimestamp "add 'latest' to versionsToCheck array"
            $versionsToCheck += "latest"
        }
        if ($allowFallbackToPrereleaseVersion -or $isPrereleaseVersionPackage)
        {
            Write-HostWithTimestamp "add 'latest-prerelease' to versionsToCheck array"
            $versionsToCheck += "latest-prerelease"
        }
    }
    else
    {
        Write-HostWithTimestamp "add 'requestedVersion' $requestedVersion to versionsToCheck array"
        $versionsToCheck += $requestedVersion
    }

    $packageVersion = $null
    foreach ($versionToCheck in $versionsToCheck)
    {
        Write-HostWithTimestamp "Try checking version $versionToCheck for package $packageName..."

        $isReleaseVersionPackage = $versionToCheck -eq "latest"
        $isPrereleaseVersionPackage = $versionToCheck -eq "latest-prerelease"

        Write-HostWithTimestamp "isReleaseVersionPackage is $isReleaseVersionPackage"
        Write-HostWithTimestamp "isPrereleaseVersionPackage is $isPrereleaseVersionPackage"

        if ($isReleaseVersionPackage -or $isPrereleaseVersionPackage)
        {
            Write-HostWithTimestamp "start to call GetPackageLatestVersion"
            $packageVersion = GetPackageLatestVersion($nugetExeDestination) ($packageName) ($nugetConfigDestination) ($maxRetryCount) ($isPrereleaseVersionPackage) ($cachedPackageVersions)
        }
        else
        {
            Write-HostWithTimestamp "Use $versionToCheck as package version"
            $packageVersion = $versionToCheck
        }

        if ([string]::IsNullOrEmpty($minAllowedVersion))
        {
            Write-HostWithTimestamp "minAllowedVersion is null or empty"
            break
        }

        $packageVersionString = $packageVersion.Split("-")[0]
        if ([version]$packageVersionString -lt [version]$minAllowedVersion)
        {
            Write-HostWithTimestamp "Current package $packageName of version $packageVersion is not supported to run with the script. Minimum allowed package version is $minAllowedVersion."
            $packageVersion = $null
        }
        else
        {
            Write-HostWithTimestamp "packageVersion $packageVersionString is equal or larger than minAllowedVersion $minAllowedVersion"
            break
        }
    }

    return $packageVersion
}

Function GetJsonContent([string]$jsonFilePath)
{
    try {
        $jsonContent = Get-Content $jsonFilePath -Raw -Encoding UTF8
        return $jsonContent | ConvertFrom-Json
    }
    catch {
        Write-Callstack
        Write-Error "Invalid JSON file $jsonFilePath. JSON content detail: $jsonContent" -ErrorAction Continue
        throw
    }
}

Function ConvertToJsonSafely {
    param([string]$content)
    process { $_ | ConvertTo-Json -Depth 99 }
}

Function CloneParameterDictionaryWithContext
{
    param (
        [parameter(mandatory=$true)]
        [hashtable]$currentDictionary, 
        [parameter(mandatory=$true)]
        [hashtable]$context
    )

    $ParameterDictionary = $currentDictionary.Clone()
    $ParameterDictionary.context = $context

    return $ParameterDictionary
}

Function MergeBuildConfigWithParameters([object]$buildConfig)
{
    foreach ($item in $buildConfig.PSObject.Properties)
    {
        if (Get-Variable $item.Name -Scope "Script" -ErrorAction SilentlyContinue)
        {
            $existVariable = Get-Variable $item.Name -Scope "Script"
            if ($item.Value -ne $existVariable)
            {
                Write-Warning "Value of config item $($item.Name) is different from remote publish config($($item.Value)) with the value you give($existVariable), but the value you give will be used"
            }
        }
        else
        {
            Set-Variable -Name $item.Name -Value $item.Value -Scope "Script" -Force
            Write-HostWithTimestamp "Create script scope variable($($item.Name)) with value($($item.Value)) from remote publish config file"
        }
    }
}

Function ParseConfigForLocalBuild([string]$buildConfigFile, [bool]$forceDownload, [string]$reportFilePath)
{
    # Download nuget
    $nugetConfigDestination = "$localBuildResourceFolder\Tools\Nuget\Nuget.Config"
    $nugetExeDestination = "$localBuildResourceFolder\Tools\Nuget\nuget.exe"
    $resourceContainerUrl = $systemDefaultVariables.ResourceContainerUrl
    $nugetConfigSource = "$resourceContainerUrl/Tools/Nuget/Nuget.Config"
    $nugetExeSource = "$resourceContainerUrl/Tools/Nuget/nuget.exe"

    echo "Download Nuget tool and config" | timestamp
    DownloadFile($nugetExeSource) ($nugetExeDestination) ($false) ($systemDefaultVariables.DownloadNugetExeTimeOutInSeconds)
    DownloadFile($nugetConfigSource) ($nugetConfigDestination) ($false) ($systemDefaultVariables.DownloadNugetConfigTimeOutInSeconds)

    # Restore local-build-config-parser package
    $packagesDestination = "$localBuildResourceFolder\packages.config"
    GeneratePackagesConfig($packagesDestination) (@($localBuildConfigParserPackage)) ($nugetExeDestination)

    echo "Restore local-build-config-parser package: $($localBuildConfigParserPackage.id)" | timestamp
    $restoreSucceeded = RestorePackage($nugetExeDestination) ($packagesDestination) ($localBuildPackagesDirectory) ($nugetConfigDestination)
    if (!$restoreSucceeded)
    {
        echo "Restore local-build-config-parser package failed" | timestamp
        exit 1
    }

    # Config parse
    $configParserExe = "$localBuildPackagesDirectory\$($localBuildConfigParserPackage.id).$($localBuildConfigParserPackage.actualVersion)\tools\Microsoft.OpenPublishing.Build.Applications.prepareConfigForLocalBuild.exe"
    $allArgs = @("-b", "$buildConfigFile", "-f", "$localBuildResourceFolder", "-l", "$reportFilePath")
    if($forceDownload)
    {
        $allArgs += ("--force-download")
    }
    echo "$configParserExe $allArgs" | timestamp
    & "$configParserExe" $allArgs
    $buildConfigFilePath = "$localBuildResourceFolder\buildConfig.json"
    if (($LASTEXITCODE -ne 0) -or (!(IsPathExists($buildConfigFilePath))))
    {
        Write-Error "call $configParserExe to parse build config for local build failed"
        exit 1
    }

    $buildConfig = (Get-Content $buildConfigFilePath -Raw) | ConvertFrom-Json

    # Merge config to parameters
    MergeBuildConfigWithParameters($buildConfig)
}

# Step-1: Parse parameters
echo "Default system value:" $systemDefaultVariables | timestamp
echo "Parse parameters $parameters" | timestamp
ParseParameters($parameters)

# Step-2: Clean up reports
$LogOutputFolder = GetValueFromVariableName($LogOutputFolder) ($systemDefaultVariables.LogOutputFolder)
if (-Not (IsPathExists($LogOutputFolder)))
{
    New-Item -ItemType directory -Path $LogOutputFolder
}
$reportFilePath = JoinPath ($LogOutputFolder) (@("report.txt"))

if (IsPathExists($reportFilePath))
{
    echo "cleaning up $reportFilePath..." | timestamp
    Remove-Item -Path $reportFilePath -Force
}

# Step-2-2: Prepare config file for local build
$buildConfigFile = GetValueFromVariableName($buildConfigFile) ($null)
$resourceContainerUrl = GetValueFromVariableName($resourceContainerUrl) ($systemDefaultVariables.ResourceContainerUrl)
$isLocalBuildWithBuildConfig = $false
$isProduction = $resourceContainerUrl.StartsWith("https://opbuildstorageprod.blob.core.windows.net")
if(!$isProduction)
{
    $localBuildConfigParserPackage.version = "latest-prerelease"
}
if (![string]::IsNullOrEmpty($buildConfigFile)) {
    echo "Prepare config for localbuild" | timestamp
    $forceDownload = ParseBoolValue("forceDownload") ($forceDownload) ($false)
    ParseConfigForLocalBuild($buildConfigFile) ($forceDownload) ($reportFilePath)
    $isLocalBuildWithBuildConfig = $true
}
else {
    Write-HostWithTimestamp "There is no BuildConfigFile parameter, build with systemDefaultVariables"
}

# Step-3: Parse publish configuration
$publishConfigFile = "$repositoryRoot\.openpublishing.publish.config.json"
CheckPath($publishConfigFile)
$publishConfigContent = (Get-Content $publishConfigFile -Raw) | ConvertFrom-Json

# Get config package information
echo "Create packages.config for entry-point package" | timestamp
$configPackageVersion = $publishConfigContent.package_version
if (![string]::IsNullOrEmpty($configPackageVersion))
{
    $entryPointPackage.version = $configPackageVersion
}

# Retrieve targets from system predefined targets
$Targets = GetValueFromVariableName($Targets) ($systemDefaultVariables.MdprojTargets)

if (-Not $systemDefaultTargets.ContainsKey("$Targets"))
{
    Throw [System.NotSupportedException] "Targets $Targets is not supported"
}

$currentTargets = $systemDefaultTargets.$Targets

# Pass user input for generate pdf target if need to resolve external link.
if ($Targets -eq 'generatePdf')
{
    $NeedResolveLink = GetValueFromVariableName($NeedResolveLink) ($false)
    if ($NeedResolveLink -eq $true)
    {
        $systemDefaultVariables.NeedGeneratePdfExternalLink = $true
        foreach ($docset in $publishConfigContent.docsets_to_publish)
        {
            $hostUrl = Read-Host "Please enter $($docset.docset_name)'s host url:"
            $basePath = Read-Host "Please enter $($docset.docset_name)'s base path:"

            $currentDictionary.environment.pdfParameters = @{}
            $currentDictionary.environment.pdfParameters.$($docset.docset_name) = @{}
            $currentDictionary.environment.pdfParameters.$($docset.docset_name).hostUrl = $hostUrl
            $currentDictionary.environment.pdfParameters.$($docset.docset_name).basePath = $basePath
        }
    }
}

# Step-4: Parse environment resources
$EnvironmentResourcesFile = GetValueFromVariableName($EnvironmentResourcesFile) ($systemDefaultVariables.EnvironmentResourcesFile)

$environmentResources = @{}
if (![string]::IsNullOrEmpty($EnvironmentResourcesFile) -and (IsPathExists($EnvironmentResourcesFile)))
{
    $environmentResources = (Get-Content $EnvironmentResourcesFile -Raw) | ConvertFrom-Json
}

# Step-5: Parse last repo status file
$useTemplateWithCachedCommitId = ParseBoolValue("UseTemplateWithCachedCommitId") ($UseTemplateWithCachedCommitId) ($systemDefaultVariables.UseTemplateWithCachedCommitId)

$cacheFolder = GetValueFromVariableName($CacheFolder) ($systemDefaultVariables.CacheFolder)
$repoStatusFilePath = JoinPath($cacheFolder) (@("repo-status.json"))
$lastRepoStatus = $null
if (IsPathExists($repoStatusFilePath))
{
    try
    {
        $lastRepoStatus = GetJsonContent($repoStatusFilePath)
        $lastRepoStatusString = $lastRepoStatus | ConvertToJsonSafely
        echo "Last repo status recorded in $repoStatusFilePath : $lastRepoStatusString" | timestamp
    }
    catch
    {
        $lastRepoStatus = $null
        echo "Failed reading $repoStatusFilePath, ignore flag of using cached template and build packages: $_.Exception.Message" | timestamp
    }
}

$nugetConfigDestination = "$workingDirectory\Tools\Nuget\Nuget.Config"
$nugetExeDestination = "$workingDirectory\Tools\Nuget\nuget.exe"

if ($publishConfigContent.use_docfxv3)
{
    $currentDictionary.environment.useDocfxV3 = ParseBoolValue("UseDocfxV3") ($publishConfigContent.use_docfxv3) ($systemDefaultVariables.UseDocfxV3)
}

if ($currentTargets.NeedInit -eq $true)
{
    # Step-5: Download Nuget tools and nuget config
    echo "Download Nuget tool and config" | timestamp

    # Trace one log to tell user currently it's internal environment.
    if ($resourceContainerUrl.StartsWith("https://opbuildstorageprod.blob.core.windows.net"))
    {
        echo "Running script within internal environment." | timestamp
    }

    $nugetConfigSource = "$resourceContainerUrl/Tools/Nuget/Nuget.Config"
    $nugetExeSource = "$resourceContainerUrl/Tools/Nuget/nuget.exe"

    $DownloadNugetExeTimeOutInSeconds = GetValueFromVariableName($DownloadNugetExeTimeOutInSeconds) ($systemDefaultVariables.DownloadNugetExeTimeOutInSeconds)
    $DownloadNugetConfigTimeOutInSeconds = GetValueFromVariableName($DownloadNugetConfigTimeOutInSeconds) ($systemDefaultVariables.DownloadNugetConfigTimeOutInSeconds)
    $UpdateNugetExe = ParseBoolValue("UpdateNugetExe") ($UpdateNugetExe) ($systemDefaultVariables.UpdateNugetExe)
    DownloadFile($nugetExeSource) ($nugetExeDestination) ($UpdateNugetExe) ($DownloadNugetExeTimeOutInSeconds)
    $UpdateNugetConfig = ParseBoolValue("UpdateNugetConfig") ($UpdateNugetConfig) ($systemDefaultVariables.UpdateNugetConfig)
    DownloadFile($nugetConfigSource) ($nugetConfigDestination) ($UpdateNugetConfig) ($DownloadNugetConfigTimeOutInSeconds)

    # Sets preserved xref service endpoint by environment.
    if ($isProduction)
    {
        $currentDictionary.environment.preservedXrefServiceEndpoint = $preservedXrefServiceEndpointByEnvironment.Production
    }
    else
    {
        $currentDictionary.environment.preservedXrefServiceEndpoint = $preservedXrefServiceEndpointByEnvironment.NonProduction
        if ($publishConfigContent.xref_endpoint -and ![String]::IsNullOrEmpty($publishConfigContent.xref_endpoint))
        {
            $currentDictionary.environment.customizedXrefServiceEndpoint = $publishConfigContent.xref_endpoint
        }
    }

    # Step-6: Create packages.config for entry-point package. For non-PROD env, treat latest version as latest-prerelease version by default
    $treatLatestVersionAsLatestPrereleaseVersion = !$isProduction
    if ($_op_treatLatestVersionAsLatestPrereleaseVersion)
    {
        $treatLatestVersionAsLatestPrereleaseVersion = $_op_treatLatestVersionAsLatestPrereleaseVersion -eq "true"
    }

    if ($treatLatestVersionAsLatestPrereleaseVersion -and $entryPointPackage.version -eq "latest")
    {
        $entryPointPackage.version = "latest-prerelease"
        echo "Use latest-prerelease version instead of latest version." | timestamp
    }

    # use cached entry-point package version if necessary
    $lastRepoStatusToResolveEntryPointPackageVersion = $null
    if ($useTemplateWithCachedCommitId -and !$currentDictionary.environment.useDocfxV3)
    {
        $lastRepoStatusToResolveEntryPointPackageVersion = $lastRepoStatus
    }

    $minimumEntryPointPackageVersion = $systemDefaultVariables.MinimumEntryPointPackageVersion
    $entryPointPackageVersion = GetPackageVersionWithMinimumRequiredVersionCheck($nugetExeDestination) ($entryPointPackage.id) ($nugetConfigDestination) ($maxRetryCount) ($entryPointPackage.version) ($treatLatestVersionAsLatestPrereleaseVersion) ($minimumEntryPointPackageVersion) ($lastRepoStatusToResolveEntryPointPackageVersion) ($environmentResources.PackageVersion)
    if ($entryPointPackageVersion -eq $null)
    {
        $errorMessage = "Cannot find package $($entryPointPackage.id) of requested version $($entryPointPackage.version) that meets the requirement of minimum version $minimumEntryPointPackageVersion to run with the script. Please check the version specified in publishing config and retry building your content. If the issue still happens, open a ticket in http://SiteHelp."
        echo $errorMessage | timestamp
        exit ConsoleErrorAndExit($errorMessage) (1)
    }

    $entryPointPackage.version = $entryPointPackageVersion

    $packagesDestination = "$workingDirectory\packages.config"

    GeneratePackagesConfig($packagesDestination) (@($entryPointPackage)) ($nugetExeDestination) ($environmentResources.PackageVersion)

    # Step-7: Restore entry-point package
    echo "Restore entry-point package: $($entryPointPackage.id)" | timestamp
    $restoreSucceeded = RestorePackage($nugetExeDestination) ($packagesDestination) ($packagesDirectory) ($nugetConfigDestination)
    if (!$restoreSucceeded)
    {
        echo "Restore entry-point package failed" | timestamp
        exit 1
    }
}
else
{
    if(!(Test-Path "$lastOpScriptVersionRecordFile"))
    {
        echo "Please run a non local build at first to restore the necessary packages and files."
        exit 1;
    }

    # TODO: check whether the actual version has a legal version stype
    $entryPointPackage.actualVersion = (Get-Content $lastOpScriptVersionRecordFile -Raw).Trim()
}

# Step-8: Call build entry point
$BuildType = GetValueFromVariableName($BuildType) ($systemDefaultVariables.BuildType)
$entryPointPackage.packageRootFolder = Join-Path $packagesDirectory -ChildPath "$($entryPointPackage.id).$($entryPointPackage.actualVersion)"
$packageToolsDirectory = Join-Path $entryPointPackage.packageRootFolder -ChildPath "tools"
$buildEntryPointDestination = Join-Path $packageToolsDirectory -ChildPath "build.entrypoint.ps1"
$isPullRequest = $BuildType -eq "PullRequest"
$isCustomValidationEnabled = ParseBoolValue("EnableCustomValidation") ($EnableCustomValidation) ($systemDefaultVariables.EnableCustomValidation)
if($isCustomValidationEnabled)
{
    # This config is for backward compatibility, it will works when there is no new validation config
    $enableValidationDefaultValue = ParseBoolValue("enable_custom_validation") ($publishConfigContent.enable_custom_validation) ($false)
    if($isPullRequest)
    {
        $isCustomValidationEnabled = ParseBoolValue("enable_pull_request_custom_validation") ($publishConfigContent.enable_pull_request_custom_validation) ($enableValidationDefaultValue)
    }
    else
    {
        $isCustomValidationEnabled = ParseBoolValue("enable_branch_build_custom_validation") ($publishConfigContent.enable_branch_build_custom_validation) ($enableValidationDefaultValue)
    }
}

if($isCustomValidationEnabled)
{
    $validationConfigFileApiUrlValue = GetValueFromVariableName($ValidationConfigFileApiUrl) ($null)
    if([string]::IsNullOrEmpty($validationConfigFileApiUrlValue))
    {
        $isCustomValidationEnabled = $false
    }
}

$currentDictionary.environment.repositoryRoot = $repositoryRoot
$currentDictionary.environment.cacheFolder = $cacheFolder
$currentDictionary.environment.outputFolder = GetValueFromVariableName($OutputFolder) ($systemDefaultVariables.OutputFolder)
$currentDictionary.environment.logOutputFolder = GetValueFromVariableName($LogOutputFolder) ($systemDefaultVariables.LogOutputFolder)
$currentDictionary.environment.reportFilePath = $reportFilePath
$currentDictionary.environment.workingDirectory = $workingDirectory
$currentDictionary.environment.systemDefaultVariables = $systemDefaultVariables
$currentDictionary.environment.packagesDirectory = $packagesDirectory
$currentDictionary.environment.nugetConfigDestination = $nugetConfigDestination
$currentDictionary.environment.nugetExeDestination = $nugetExeDestination
$currentDictionary.environment.currentTargets = $currentTargets
$currentDictionary.environment.treatLatestVersionAsLatestPrereleaseVersion = $treatLatestVersionAsLatestPrereleaseVersion
$currentDictionary.environment.LastOpScriptVersion = $entryPointPackage.actualVersion
$currentDictionary.environment.LastOpScriptVersionRecordFile = $lastOpScriptVersionRecordFile
$currentDictionary.environment.EnvironmentResources = $environmentResources
$currentDictionary.environment.defaultErrorLogCodesString = GetValueFromVariableName($DefaultErrorLogCodesString) ($systemDefaultVariables.DefaultErrorLogCodesString)
$currentDictionary.environment.defaultWarningLogCodesString = GetValueFromVariableName($DefaultWarningLogCodesString) ($systemDefaultVariables.DefaultWarningLogCodesString)
$currentDictionary.environment.defaultInfoLogCodesString = GetValueFromVariableName($DefaultInfoLogCodesString) ($systemDefaultVariables.DefaultInfoLogCodesString)
$currentDictionary.environment.defaultIntellisenseErrorLogCodes = GetValueFromVariableName($DefaultIntellisenseErrorLogCodes) ($systemDefaultVariables.DefaultIntellisenseErrorLogCodes)
$currentDictionary.environment.defaultIntellisenseWarningLogCodes = GetValueFromVariableName($DefaultIntellisenseWarningLogCodes) ($systemDefaultVariables.DefaultIntellisenseWarningLogCodes)
$currentDictionary.environment.defaultIntellisenseInfoLogCodes = GetValueFromVariableName($DefaultIntellisenseInfoLogCodes) ($systemDefaultVariables.DefaultIntellisenseInfoLogCodes)
$currentDictionary.environment.enableBuildToolDebugModel = ParseBoolValue("EnableBuildToolDebugModel") ($EnableBuildToolDebugModel) ($systemDefaultVariables.EnableBuildToolDebugModel)
$currentDictionary.environment.enableFileMapGenerator = ParseBoolValue("EnableFileMapGenerator") ($EnableFileMapGenerator) ($systemDefaultVariables.EnableFileMapGenerator)
$currentDictionary.environment.enableXrefmapResolver = ParseBoolValue("EnableXrefmapResolver") ($EnableXrefmapResolver) ($systemDefaultVariables.EnableXrefmapResolver)
$currentDictionary.environment.enableFallbackPlugin = ParseBoolValue("EnableFallbackPlugin") ($EnableFallbackPlugin) ($systemDefaultVariables.EnableFallbackPlugin)
$currentDictionary.environment.enableIncrementalBuild = ParseBoolValue("EnableIncrementalBuild") ($EnableIncrementalBuild) ($systemDefaultVariables.EnableIncrementalBuild)
$currentDictionary.environment.pdfTemplateFolder = GetValueFromVariableName($PdfTemplateFolder) ($systemDefaultVariables.PdfTemplateFolder)
$currentDictionary.environment.needGeneratePdfExternalLink = ParseBoolValue("NeedGeneratePdfExternalLink") ($NeedGeneratePdfExternalLink) ($systemDefaultVariables.NeedGeneratePdfExternalLink)
$currentDictionary.environment.pdfConvertParallelism = GetValueFromVariableName($PdfConvertParallelism) ($systemDefaultVariables.PdfConvertParallelism)
$currentDictionary.environment.enablePdfHeaderFooter = ParseBoolValue("EnablePdfHeaderFooter") ($EnablePdfHeaderFooter) ($systemDefaultVariables.EnablePdfHeaderFooter)
$currentDictionary.environment.defaultSubmoduleBranch = GetValueFromVariableName($DefaultSubmoduleBranch) ($systemDefaultVariables.DefaultSubmoduleBranch)
$currentDictionary.environment.enableMasterRedirectionFile = ParseBoolValue("EnableMasterRedirectionFile") ($EnableMasterRedirectionFile) ($systemDefaultVariables.EnableMasterRedirectionFile)
$currentDictionary.environment.azureLocalizedRepositoryUrlFormat = GetValueFromVariableName($AzureLocalizedRepositoryUrlFormat) ($systemDefaultVariables.AzureLocalizedRepositoryUrlFormat)
$currentDictionary.environment.contributionBranch = GetValueFromVariableName($ContributionBranch) ($systemDefaultVariables.ContributionBranch)
$currentDictionary.environment.newtonsoftJsonSchemaLicense = GetValueFromVariableName($NewtonsoftJsonSchemaLicense) ($null)
$currentDictionary.environment.validationConfigFileApiUrl = $validationConfigFileApiUrlValue
$currentDictionary.environment.enableCustomValidation = $isCustomValidationEnabled
$currentDictionary.environment.forceInitialize = ParseBoolValue("ForceInitialize") ($ForceInitialize) ($systemDefaultVariables.ForceInitialize)
$currentDictionary.environment.abandonGitUserProfileLocalCache = ParseBoolValue("AbandonGitUserProfileLocalCache") ($AbandonGitUserProfileLocalCache) ($systemDefaultVariables.AbandonGitUserProfileLocalCache)
$currentDictionary.environment.resourceContainerUrl = $resourceContainerUrl

# If use docfx v3, directly call new ps1 to execute docfx
if ($currentDictionary.environment.useDocfxV3)
{
    $buildEntryPointDestination = Join-Path $packageToolsDirectory -ChildPath "docsv3/docsv3.ps1"
    echo "Call build entry point at $buildEntryPointDestination" | timestamp
    & "$buildEntryPointDestination" $currentDictionary
    exit $LASTEXITCODE
}

$env:_op_enableCustomValidation = $isCustomValidationEnabled

$entryPointPackageActualVersion = $entryPointPackage.actualVersion
$entryPointPackageActualVersionString = $entryPointPackageActualVersion.Split('-')[0]
$normalizeContentInBuildTool = ParseBoolValue("NormalizeContentInBuildTool") ($NormalizeContentInBuildTool) ($systemDefaultVariables.NormalizeContentInBuildTool)
$enableIncrementalPostProcessing = ParseBoolValue("EnableIncrementalPostProcessing") ($EnableIncrementalPostProcessing)($systemDefaultVariables.EnableIncrementalPostProcessing)
if ([version]$entryPointPackageActualVersionString -lt "1.27.0")
{
    if ($normalizeContentInBuildTool)
    {
        echo "Set normalizing content in build tool to false as current version of entry point package $entryPointPackageActualVersion does not meet the minimum requirement to enable it." | timestamp
        $normalizeContentInBuildTool = $false
    }

    if ($enableIncrementalPostProcessing)
    {
        echo "Set incremental postprocessing to false as current version of entry point package $entryPointPackageActualVersion does not meet the minimum requirement to enable it." | timestamp
        $enableIncrementalPostProcessing = $false
    }
}
$currentDictionary.environment.normalizeContentInBuildTool = $normalizeContentInBuildTool
$currentDictionary.environment.enableIncrementalPostProcessing = $enableIncrementalPostProcessing

$dependentListFilePath = GetValueFromVariableName($UserSpecifiedDependentListFilePath) ($systemDefaultVariables.UserSpecifiedDependentListFilePath)
if ([string]::IsNullOrEmpty($dependentListFilePath))
{
    $dependentListFilePath = JoinPath($currentDictionary.environment.logOutputFolder) (@("dependent-files.txt"))
}
$currentDictionary.environment.dependentListFilePath = $dependentListFilePath

$fullDependentListFilePath= GetValueFromVariableName($FullDependentListFilePath) ($systemDefaultVariables.FullDependentListFilePath)
if ([string]::IsNullOrEmpty($fullDependentListFilePath))
{
    $fullDependentListFilePath = JoinPath($currentDictionary.environment.logOutputFolder) (@("full-dependent-files.txt"))
}
$currentDictionary.environment.fullDependentListFilePath = $fullDependentListFilePath
$currentDictionary.environment.userSpecifiedChangeListTsvFilePath = GetValueFromVariableName($UserSpecifiedChangeListTsvFilePath) ($systemDefaultVariables.UserSpecifiedChangeListTsvFilePath)

$AllowUseDynamicRendering = ParseBoolValue("AllowUseDynamicRendering") ($AllowUseDynamicRendering) ($systemDefaultVariables.AllowUseDynamicRendering)
echo "Allow use of dynamic rendering: $AllowUseDynamicRendering" | timestamp
$currentDictionary.environment.docfxAllowUseDynamicRendering = $AllowUseDynamicRendering
$currentDictionary.environment.isDynamicRendering = ParseBoolValue("IsDynamicRendering") ($IsDynamicRendering) ($systemDefaultVariables.IsDynamicRendering)

$ReplayErrorWarningLogs = ParseBoolValue("ReplayErrorWarningLogs") ($ReplayErrorWarningLogs) ($systemDefaultVariables.ReplayErrorWarningLogs)
$currentDictionary.environment.replayErrorWarningLogs = $ReplayErrorWarningLogs

$currentDictionary.environment.useTemplateWithCachedCommitId = $useTemplateWithCachedCommitId
$currentDictionary.environment.lastRepoStatus = $lastRepoStatus
$currentDictionary.environment.entryPointPackage = $entryPointPackage
$currentDictionary.environment.tocChangeTriggerFullBuild = ParseBoolValue("TocChangeTriggerFullBuild") ($TocChangeTriggerFullBuild) ($systemDefaultVariables.TocChangeTriggerFullBuild)
$currentDictionary.environment.minimumCommonPackageVersion = $systemDefaultVariables.MinimumCommonPackageVersion

$currentDictionary.environment.isServerBuild = ParseBoolValue("IsServerBuild") ($IsServerBuild) ($systemDefaultVariables.IsServerBuild)
$currentDictionary.environment.buildType = $BuildType
$currentDictionary.environment.skipDereferenceForPR = ParseBoolValue("SkipDereferenceForPR") ($SkipDereferenceForPR) ($systemDefaultVariables.SkipDereferenceForPR)
$currentDictionary.environment.copyFileFromFallbackFolders = ParseBoolValue("CopyFileFromFallbackFolders") ($CopyFileFromFallbackFolders) ($systemDefaultVariables.CopyFileFromFallbackFolders)

$currentDictionary.environment.copyFileSearchPattern = $PreservedFallbackCopyFileSearchPattern
if ($PreservedFallbackCopyFileSearchPattern -eq $null)
{
    $currentDictionary.environment.copyFileSearchPattern = $systemDefaultVariables.PreservedFallbackCopyFileSearchPattern
}
$currentDictionary.environment.copyFileSearchPatternForGeneratePdf = $CopyFileSearchPatternForGeneratePdf
if ($CopyFileSearchPatternForGeneratePdf -eq $null)
{
    $currentDictionary.environment.copyFileSearchPatternForGeneratePdf = $systemDefaultVariables.CopyFileSearchPatternForGeneratePdf
}

# If user set the non_published_copy_file_search_pattern in op config, then trust that.
if ($publishConfigContent.non_published_copy_file_search_pattern -ne $null)
{
    $currentDictionary.environment.nonPublishedCopyFileSearchPattern = $publishConfigContent.non_published_copy_file_search_pattern
}
else
{
    $currentDictionary.environment.nonPublishedCopyFileSearchPattern = $NonPublishedCopyFileSearchPattern
    if ($NonPublishedCopyFileSearchPattern -eq $null)
    {
        $currentDictionary.environment.nonPublishedCopyFileSearchPattern = $systemDefaultVariables.NonPublishedCopyFileSearchPattern
    }
}

if ($publishConfigContent.enable_git_features -ne $null)
{
    $currentDictionary.environment.enableGitFeatures = [System.Convert]::ToBoolean($publishConfigContent.enable_git_features)
}
else
{
    $currentDictionary.environment.enableGitFeatures = ParseBoolValue("EnableGitFeatures") ($EnableGitFeatures) ($systemDefaultVariables.EnableGitFeatures)
    if ($isLocalBuildWithBuildConfig)
    {
        $currentDictionary.environment.enableGitFeatures = $false
    }
}
echo "Enable git features is: $($currentDictionary.environment.enableGitFeatures)" | timestamp

$ParameterDictionary = CloneParameterDictionaryWithContext($currentDictionary) ($contextDictionary)

echo "Call build entry point at $buildEntryPointDestination" | timestamp
& "$buildEntryPointDestination" $ParameterDictionary

exit $LASTEXITCODE
