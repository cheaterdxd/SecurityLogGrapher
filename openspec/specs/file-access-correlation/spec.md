# file-access-correlation Spec

## Purpose
TBD

## Requirements

### Requirement: File Access Linking
The system SHALL link Event 4663 (File Access) to the correct process using the `machine|pid` composite key and verify `TimeCreated >= birth_time`.

#### Scenario: Process accesses a file
- **WHEN** Event 4663 occurs for a given `ProcessId`
- **THEN** the event is attached to the corresponding process node in the timeline

### Requirement: Sequential Action Detection
The system SHALL flag a file access event as sequential if its Thread ID matches the `spawning_tid` from the parent execution context.

#### Scenario: Same thread performs access
- **WHEN** Event 4663 `ThreadID` matches the `spawning_tid`
- **THEN** `is_sequential` is set to true to indicate direct causality

