# Global variables
$global:Threshold = 5
$global:InputFilePath = "internal_ip_address_blacklist_raw.txt"
$global:OutputFilePath = "internal_ip_address_blacklist_cleaned.txt"

# Function to parse the file
function Parse-File {
    param (
        [string]$filePath
    )
    Get-Content $filePath | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
}

# Function to check if the entries are valid subnets or IP addresses
function IsValid-Subnet {
    param (
        [string]$entry
    )
    if ($entry -match "^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$") {
        $parts = $entry.Split("/")
        if ($parts.Count -eq 2) {
            $prefix = [int]$parts[1]
            if ($prefix -lt 0 -or $prefix -gt 32) {
                return $false
            }
        }
        $octets = $parts[0].Split(".")
        foreach ($octet in $octets) {
            if ([int]$octet -lt 0 -or [int]$octet -gt 255) {
                return $false
            }
        }
        return $true
    }
    return $false
}

# Function to combine addresses into /24 subnets if more than the threshold have the same starting octets
function Combine-Subnets {
    param (
        [array]$entries,
        [int]$threshold
    )
    $grouped = @{}
    foreach ($entry in $entries) {
        if ($entry -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/32$") {
            $prefix = $entry.Split(".")[0..2] -join "."
            if (-not $grouped.ContainsKey($prefix)) {
                $grouped[$prefix] = @()
            }
            $grouped[$prefix] += $entry
        } else {
            $grouped[$entry] = $entry
        }
    }

    $result = @()
    foreach ($key in $grouped.Keys) {
        if ($grouped[$key].Count -ge $threshold) {
            $result += "$key.0/24"
        } else {
            $result += $grouped[$key]
        }
    }
    return $result
}

# Function to remove duplicates
function Remove-Duplicates {
    param (
        [array]$entries
    )
    $entries | Sort-Object -Unique
}

# Function to order the output by subnet size and IP address
function Order-Output {
    param (
        [array]$entries
    )
    $entries | Sort-Object {
        $subnet = $_.Split("/")[1]
        if (-not $subnet) { $subnet = 32 }
        [int]$subnet
    }, {
        [System.Net.IPAddress]::Parse($_.Split("/")[0]).GetAddressBytes()
    }
}

# Function to write the output to a new file
function Write-Output {
    param (
        [array]$entries,
        [string]$outputPath
    )
    $entries | Out-File $outputPath
}

# Main script

# Parse the file
$entries = Parse-File -filePath $global:InputFilePath

# Filter valid subnets and throw an error if any invalid entries are found
$invalidEntries = @()
$validEntries = @()

foreach ($entry in $entries) {
    if (IsValid-Subnet -entry $entry) {
        $validEntries += $entry
    } else {
        $invalidEntries += $entry
    }
}

if ($invalidEntries.Count -gt 0) {
    Write-Error "The following entries are invalid: $($invalidEntries -join ', ')"
    throw "Invalid entries detected. Please correct them before proceeding."
}

# Combine subnets
$combinedEntries = Combine-Subnets -entries $validEntries -threshold $global:Threshold

# Remove duplicates
$uniqueEntries = Remove-Duplicates -entries $combinedEntries

# Order the output
$orderedEntries = Order-Output -entries $uniqueEntries

# Write the output to a new file
Write-Output -entries $orderedEntries -outputPath $global:OutputFilePath
