# EyeSpy

<p align="Center">
<img src="https://github.com/Miiden/EyeSpy/blob/main/EyeSpyLogo.png" width="280" height="280">
</p>

EyeSpy is a tool designed to enumerate and gain access to IP Cameras via RTSP. It provides a flexible and efficient way to scan for open RTSP ports, Check if authentication is required and attempt common credential spraying attacks.

OpSec Info:
This tool is not quiet at all.

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## Introduction

EyeSpy is developed by Miiden and utilizes PowerShell to help with penetration tests and research from a windows environment.
EyeSpy is designed to enumerate and gain access to IP Cameras via RTSP. It provides a flexible and efficient way to scan for open RTSP ports, Check if authentication is required and attempt common credential spraying attacks.

## Installation

There is no specific installation required for EyeSpy. Simply download the script from the [GitHub repository](https://github.com/Miiden/EyeSpy) and run it using PowerShell.



## Usage

EyeSpy provides several command-line options to customize its behavior:

- `-Scan <IP/CIDR>`: Scan a single IP or CIDR range for open RTSP ports.

- `-NoAuth <IP/CIDR>`: Scan for open RTSP ports and spray for common paths. Returns any camera with no authentication required, by checking common camera paths with no authentication header.
  
- `-Auto <IP/CIDR>`: Perform a fully automatic scan within a specified IP range (CIDR notation). This scan will find open ports, and spray each path with combinations of common/default credentials.
  
- `-Help`: Display the help menu, showing usage instructions and examples.

## Examples


### Scan the Network Provided
```powershell
EyeSpy -Scan 192.168.0.123
```
### Path Scan
```powershell
EyeSpy -NoAuth 10.0.0.0/16
```
### Full Automatic Scan
```powershell
EyeSpy -Auto 192.168.0.1/24
```
### Display Help
```powershell
EyeSpy -Help
```

## Contributing
Contributions to EyeSpy are welcome. Feel free to fork the repository, make improvements, and submit pull requests.

## License
EyeSpy is licensed under the [MIT](https://github.com/Miiden/EyeSpy/blob/main/LICENSE.md) License.
