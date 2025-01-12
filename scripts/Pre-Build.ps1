$variablesFile = "./src/Core/Variables.cs"
$csprojFile = "./ColDog Locker.csproj"

# Fetch the version from the .csproj file
[xml]$csproj = Get-Content $csprojFile
$version = [string]$csproj.Project.PropertyGroup.Version
$version = $version.Trim()

# Create build version
$buildNumber = (Get-Date).ToString("yyyy.MMdd.HHmm")
$buildDate = (Get-Date).ToString("yyyy-MM-dd")
$buildVersion = "$version.$buildNumber"

# Read the content of Variables.cs once
$variablesContent = Get-Content $variablesFile

# Update the version
$variablesContent = $variablesContent -replace 'public const string version = ".*";', "public const string version = `"$version`";"

# Update the build version
$variablesContent = $variablesContent -replace 'public const string buildVersion = ".*";', "public const string buildVersion = `"$buildVersion`";"

# Update the build number
$variablesContent = $variablesContent -replace 'public const string buildNumber = ".*";', "public const string buildNumber = `"$buildNumber`";"

# Update the build date
$variablesContent = $variablesContent -replace 'public const string buildDate = ".*";', "public const string buildDate = `"$buildDate`";"

# Write the updated content back to Variables.cs
$variablesContent | Set-Content $variablesFile