# registry-correlation Spec

## Purpose
TBD

## Requirements

### Requirement: 3-Level Cascade Join for Registry
The system SHALL associate Event 4657 (Registry Mod) to processes using a 3-level priority join: L1 (PID + Name match), L2 (PID match, Name mismatch), and L3 (LogonScope fallback).

#### Scenario: Modern OS provides PID and Name
- **WHEN** Event 4657 contains a non-zero `ProcessId` and matching `ProcessName`
- **THEN** the join quality is marked as `L1_PID+Name`

#### Scenario: Legacy OS omits PID
- **WHEN** Event 4657 has a null or zero `ProcessId`
- **THEN** the system falls back to matching by `logon_scope` within a 30-second time window, marking join quality as `L3_LogonId_Fallback`

