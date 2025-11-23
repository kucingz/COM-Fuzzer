#  Copyright 2025 Remco van der Meer. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

<#
.SYNOPSIS
Get COM server data.
.DESCRIPTION
This cmdlet gets the COM interfaces and available procedures for COM servers and stores it in a JSON file that can be parsed to the COM-Fuzzer
.PARAMETER OutPath
Specify the directory for the json file that will be exported
.PARAMETER ClassContext
Specify the COM context for gathering a specific set of COM classes (remote, services, interactive)
.PARAMETER ComClass
Specify the COM Class target through pipe
.INPUTS
OleViewDotNet.Database.COMRegistryEntry[]
.OUTPUTS
JSON file
.EXAMPLE
Get-ComServerData -output .\output -ClassContext Services
Get's the COM interfaces and procedures for every class used by Windows services
#>
function Get-ComServerData {
    param (
        [Parameter(ValueFromPipeline = $true)]
        [OleViewDotNet.Database.COMRegistryEntry[]]$ComClass,

        [string]$ComDatabaseFile,

        [Parameter(Mandatory = $true)]
        [string]$OutPath,

        [ValidateSet("Services", "Interactive", "Remote")]
        [string]$ClassContext,

        [string]$CLSID,

        [string]$CLSIDList
    )

    begin {
        # Check if $outPath exists, if not make the directory
        if (-Not (Test-Path $OutPath)) {
            # Creating Path
            New-Item -ItemType Directory -Path $OutPath
        }

        $AllClasses = @()   
        $ComClassTargets = @()

        if ($ComDatabaseFile) {
            Write-Verbose "Loading COM classes from file: $ComDatabaseFile"
            Get-ComDatabase -Path $ComDatabaseFile
            Set-ComDatabase -Default
            $AllClasses = Get-ComClass
        }
    }

    process {
        if ($ComClass) {
            $AllClasses += $ComClass
        }
    }

    end {
        if ($CLSID) {
            # Get COM data for user specified CLSID
            $AllClasses = Get-ComClass -Clsid $CLSID
        }

        if ($CLSIDList) {
            $Entries = Get-Content $CLSIDList
            
            # Loop over entries
            $AllClasses = @()
            foreach ($clsid in $Entries) {
                $entry = Get-ComClass -Clsid $clsid
                $AllClasses += $entry
            }
        }

        # Load default database if no input and no file
        if (-not $ComDatabaseFile -and $AllClasses.Count -eq 0) {
            Write-Verbose "Loading default COM database"
            Get-ComDatabase
            Set-ComDatabase -Default
            $AllClasses = Get-ComClass
        }

        # Apply access selection
        $AllClasses = $AllClasses

        # Filter by context
        if (-not $ClassContext) {
            $ComClassTargets = $AllClasses
        } else {
            switch ($ClassContext) {
                "Services" {
                    $ComClassTargets = $AllClasses | Where-Object { $_.HasAppID -and $_.AppIDEntry.IsService }
                }
                "Interactive" {
                    $ComClassTargets = $AllClasses | Where-Object IsInteractiveUser
                }
                "Remote" {
                    foreach ($class in $AllClasses) {
                        $remoteAccess = $class | Get-ComAccess | Where-Object { $_.RemoteAccess}
                        $remoteActivate =  $class | Get-ComAccess | Where-Object { $_.RemoteActivate }
                        if ($remoteAccess -and $remoteActivate) {
                            $ComClassTargets += $class
                        }
                    }                    
                }
                default {
                    $ComClassTargets = $AllClasses
                }
            }
        }

        Write-Verbose "Filtered $($ComClassTargets.Count) classes based on context: $ClassContext"

        $excludedMethods = @(
            'Connect', 'Disconnect', 'Dispose', 'Equals', 'GetHashCode',
            'GetType', 'QueryInterface', 'ToString', 'Unwrap'
        )

        Write-Host "[+] Processing COM classess... can take a while, check with -Verbose"

        # Initialize the JSON file with opening bracket
        $outputFilePath = "$OutPath\ComServerData.json"
        "[" | Out-File $outputFilePath -Encoding utf8
        
        $processedCount = 0
        $totalCount = $ComClassTargets.Count

        foreach ($class in $ComClassTargets) {
            # Define a list of CLSIDs to skip (crashes PowerShell)
            $ExcludedCLSIDs = @(
                "63766597-1825-407d-8752-098f33846f46"
                "bdb57ff2-79b9-4205-9447-f5fe85f37312"
                "577289b6-6e75-11df-86f8-18a905160fe0"
                "581333f6-28db-41be-bc7a-ff201f12f3f6"
            )

            # Skip processing if CLSID is in exclusion list
            if ($ExcludedCLSIDs -contains $class.CLSID) {
                Continue
            }
            
            Write-Verbose "Processing: $($class.Name) - CLSID: $($class.CLSID)"
            $ClassResult = [PSCustomObject]@{
                ClassName = $class.Name
                CLSID     = $class.CLSID
                Interfaces = @()
            }

            try {
                $clsid = $class.CLSID
                $logEntry = "COM Class: $clsid`n------------------------`n"
                $logFilePath = "$OutPath\log.txt"
                $logEntry | Out-File -FilePath $logFilePath -Append -Encoding utf8
                $ComInterfaces = Get-ComInterface -Class $class
            } catch {
                Write-Verbose "[!] Error getting interfaces for class"
                continue
            }
    
            if ($ComInterfaces.Length -eq 1 -and -not $ComInterface.HasProxy -and -not $ComInterface.HasTypeLib)  {
                Continue
            }

            foreach ($ComInterface in $ComInterfaces) {
                $InterfaceResult = [PSCustomObject]@{
                    InterfaceName = $ComInterface.Name
                    IID           = $ComInterface.Iid
                    Methods       = @()
                }

                try {
                    $IntObj = New-ComObject -Class $class
                    $ComClient = Get-ComObjectInterface -Object $IntObj -Iid $ComInterface.Iid

                    $Procedures = $ComClient | Get-Member -MemberType Method | Where-Object {
                        ($excludedMethods -notcontains $_.Name) -and
                        (-not $_.Name.StartsWith('get_')) -and
                        (-not $_.Name.StartsWith('set_'))
                    }

                    foreach ($Procedure in $Procedures) {
                        $InterfaceResult.Methods += $Procedure.Definition
                    }
                } catch {
                    Write-Verbose "[!] Error creating COM object for interface"
                }

                $ClassResult.Interfaces += $InterfaceResult
            }

            # Convert to JSON and format
            $jsonOutput = $ClassResult | ConvertTo-Json -Depth 5 | Format-Json -Indentation 2
            
            # Add proper indentation for the array element
            $indentedJson = $jsonOutput -split "`n" | ForEach-Object { "  " + $_ }
            $indentedJson = $indentedJson -join "`n"
            
            # Append to file with comma if not the last item
            $processedCount++
            if ($processedCount -lt $totalCount) {
                $indentedJson + "," | Out-File $outputFilePath -Append -Encoding utf8
            } else {
                $indentedJson | Out-File $outputFilePath -Append -Encoding utf8
            }
            
            Write-Verbose "Appended class $processedCount/$totalCount to JSON file"
        }

        # Close the JSON array
        "]" | Out-File $outputFilePath -Append -Encoding utf8
        
        Write-Host "[+] Exported $processedCount COM classes to $outputFilePath"
    }
}

<#
.SYNOPSIS
Formats a JSON file to fix large indents
.DESCRIPTION
This function formats a JSON file to fix large indents
#>
function Format-Json
{
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [String]$Json,
 
        [ValidateRange(1, 1024)]
        [Int]$Indentation = 2
    )
 
    $lines = $Json -split '\n'
 
    $indentLevel = 0
 
    $result = $lines | ForEach-Object `
    {
        if ($_ -match "[\}\]]")
        {
            $indentLevel--
        }
 
        $line = (' ' * $indentLevel * $Indentation) + $_.TrimStart().Replace(":  ", ": ")
 
        if ($_ -match "[\{\[]")
        {
            $indentLevel++
        }
 
        return $line
    }
 
    return $result -join "`n"
}