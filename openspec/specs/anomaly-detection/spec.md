# anomaly-detection Spec

## Purpose
TBD

## Requirements

### Requirement: PPID Spoofing Detection
The system SHALL flag PPID Spoofing if a process claims a parent that exited before the child was created.

#### Scenario: Parent death precedes child birth
- **WHEN** a parent process's Event 4689 occurs before its presumed child's Event 4688 `TimeCreated`
- **THEN** the child is flagged for PPID Spoofing with HIGH severity

### Requirement: UAC Token Merge
The system SHALL link corresponding elevated and standard tokens for the same user logon.

#### Scenario: User logs in interactively
- **WHEN** two Event 4624s occur near-simultaneously for the same user with paired `ElevatedToken` values
- **THEN** their scopes are linked into a single logical user session

### Requirement: LOLBin Detection
The system SHALL flag recognized legitimate binaries abused maliciously based on `CommandLine` patterns.

#### Scenario: CertUtil used to download files
- **WHEN** `proc_name` matches `certutil` and `cmd_line` contains `-urlcache`
- **THEN** the event is flagged as suspicious with HIGH severity

