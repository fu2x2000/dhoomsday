
# Doomsday Script

## Overview

The Doomsday Script is a PowerShell-based tool designed to monitor for process injections on Windows systems. It serves as a backup solution for traditional Endpoint Detection and Response (EDR) systems, providing real-time detection of suspicious activities when primary EDR solutions might be offline or compromised.

## Recent Context

Due to the recent disruptions caused by CrowdStrike's Falcon EDR product, which led to widespread Windows outages, the Doomsday Script offers a critical backup solution. It ensures continuous protection by monitoring process injections and providing alerts even when primary security systems fail.

## Features

- Real-time monitoring of process creation.
- Detection of process injections by examining memory protection flags.
- Continuous logging of suspicious activities.
- Manual termination capability.

## Requirements

- Windows operating system (Windows 7 or later recommended).
- PowerShell 5.1 or later.
- Administrator privileges to run the script.

## Installation

1. **Open PowerShell as Administrator:**
   - Right-click on the PowerShell icon and select "Run as administrator".

2. **Download or Copy the Script:**
   - Copy the script code provided in the `MonitorProcesses.ps1` file.

3. **Save the Script:**
   - Save the script code to a file named `MonitorProcesses.ps1`.

## Usage

1. **Navigate to the Script Directory:**
   - Open PowerShell and use the `cd` command to change to the directory where `MonitorProcesses.ps1` is saved.

   ```powershell
   cd path\to\script
   ```

2. **Run the Script:**
   - Execute the script with the following command:

   ```powershell
   .\MonitorProcesses.ps1
   ```

3. **Stopping the Script:**
   - To stop the script, simply press `CTRL + C` in the PowerShell window.

## Script Breakdown

1. **Add-Type Definition:**
   - Defines the necessary structures and P/Invoke signatures for memory inspection.

2. **Check-MemoryRegions Function:**
   - Examines the memory regions of processes for the `PAGE_EXECUTE_READWRITE` flag, which indicates potential process injection.

3. **WMI Event Query:**
   - Continuously monitors for new process creation events using Windows Management Instrumentation (WMI).

4. **Register-WmiEvent Action:**
   - Retrieves and inspects details of new processes, logging any suspicious activities.

5. **Infinite Loop with Key Press Detection:**
   - Keeps the script running indefinitely, allowing manual termination with a key press.

## Example Output

When a suspicious process injection is detected, the script outputs a message similar to:

```
Monitoring process creation for potential injections...
Press any key to stop...
Error accessing process 12345: Error message
```

## Contributing

If you have suggestions or improvements for the Doomsday Script, please feel free to contribute by submitting a pull request. Your feedback and contributions are greatly appreciated.

## License

The Doomsday Script is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Disclaimer

The Doomsday Script is provided as-is, without any warranties or guarantees. Use it at your own risk and ensure you comply with all applicable laws and regulations.

## Contact

For any questions or support, please contact [your email address] or visit [your website or GitHub profile].
