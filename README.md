# Precise Reimplementation of NtCreateLowBoxToken System Call

A meticulously reverse-engineered implementation of the Windows NT kernel's NtCreateLowBoxToken native system call. This sophisticated reimplementation provides a comprehensive and binary-compatible replacement for the original system call functionality, with particular emphasis on security token manipulation and process isolation mechanisms.

## Architectural Overview

This repository presents an independently developed reproduction of the `NtCreateLowBoxToken` native API implementation, a critical component in Windows security token manipulation and process isolation architecture. The implementation has been systematically reconstructed through precise reverse engineering of Windows 11 24H2 system call interfaces, ensuring behavioral consistency with the native implementation at the binary level.

## Technical Capabilities

- Binary-compatible replacement for the native NtCreateLowBoxToken system call interface
- Precise reproduction of Windows 11 24H2's internal token manipulation mechanisms
- Comprehensive support for AppContainer security context creation and management
- Kernel-mode driver implementation for system call interception
- Demonstration of programmatic security boundary establishment

## Platform Compatibility Matrix

Extensively validated across contemporary Windows NT-based operating systems:
- Windows 11 Version 24H2 (10.0.26100.2605)
- Windows 11 Version 23H2 (10.0.22631.4602)
- Windows 10 Version 22H2 (10.0.19045.5247)

## Demonstration Implementation
The repository incorporates a comprehensive demonstration application that:

Facilitates kernel-mode driver installation and initialization

Implements system call interception mechanisms

Demonstrates programmatic AppContainer security context establishment

Executes Notepad.exe within an AppContainer security boundary

The demonstration utilizes select components from MalwareTech's AppContainerSandbox implementation

## Repository Architecture

├── driver/             # Kernel-mode implementation

└── tests/             # Validation suite

## Build Requirements
Prerequisites

Microsoft Visual Studio 2022 Development Environment

Windows Driver Development Kit (WDK)

Windows Software Development Kit (SDK) 10.0.22621.0 or subsequent releases

## Attribution
Demonstration implementation incorporates components from MalwareTech's AppContainerSandbox

## Licensing
This implementation is distributed under the GNU General Public License v3.0. Refer to the LICENSE document for comprehensive terms.

## Implementation Notes
Independent implementation, not affiliated with Microsoft Corporation

Implementation deployed at operator's discretion

Not recommended for production environment deployment

## Community Participation
Technical contributions are welcomed. Please initiate discussion through issue submission prior to modification proposals.
