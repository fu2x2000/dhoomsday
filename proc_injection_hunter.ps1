<#
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Author: FU2X2000
Year: [2024]
#>

# Define the MEMORY_BASIC_INFORMATION structure and other required P/Invoke signatures
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [Flags]
    public enum AllocationProtect : uint {
        PAGE_EXECUTE_READWRITE = 0x40
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public AllocationProtect AllocationProtect;
        public UIntPtr RegionSize;
        public uint State;
        public AllocationProtect Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
}
"@

# Function to check memory regions of a process for PAGE_EXECUTE_READWRITE protection
function Check-MemoryRegions {
    param (
        [int]$processId
    )

    $PROCESS_QUERY_INFORMATION = 0x0400
    $PROCESS_VM_READ = 0x0010
    $memoryProtectionFlag = [Win32+AllocationProtect]::PAGE_EXECUTE_READWRITE

    try {
        $processHandle = [Win32]::OpenProcess($PROCESS_QUERY_INFORMATION -bor $PROCESS_VM_READ, $false, $processId)

        if ($processHandle -eq [IntPtr]::Zero) {
            Write-Warning "Could not open process $processId. Insufficient permissions or process does not exist."
            return $false
        }

        $baseAddress = [IntPtr]::Zero
        $memoryInfo = New-Object Win32+MEMORY_BASIC_INFORMATION
        $memoryInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf($memoryInfo)

        while ([Win32]::VirtualQueryEx($processHandle, $baseAddress, [ref]$memoryInfo, [uint32]$memoryInfoSize) -ne 0) {
            if ($memoryInfo.Protect -eq $memoryProtectionFlag) {
                [Win32]::CloseHandle($processHandle)
                return $true
            }
            $baseAddress = [IntPtr]::Add($memoryInfo.BaseAddress, [int64]$memoryInfo.RegionSize.ToUInt64())
        }

        [Win32]::CloseHandle($processHandle)
    } catch {
        Write-Host "Error accessing process ${processId}: $_"
    }

    return $false
}

# WMI event query to monitor process creation
$query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"

# Register the WMI event
Register-WmiEvent -Query $query -Action {
    $process = $event.SourceEventArgs.NewEvent.TargetInstance
    $processId = $process.ProcessId
    $processName = $process.Name

    Write-Host "Process created: PID = ${processId}, Name = ${processName}"

    if (Check-MemoryRegions -processId $processId) {
        Write-Host "Suspicious process detected: PID = ${processId}, Name = ${processName}"
    }
}

Write-Host "Monitoring process creation for potential injections..."
Write-Host "Press any key to stop..."

while ($true) {
    Start-Sleep -Seconds 1
    if ([Console]::KeyAvailable) {
        $null = [Console]::ReadKey($true)
        break
    }
}

Write-Host "Monitoring stopped."
