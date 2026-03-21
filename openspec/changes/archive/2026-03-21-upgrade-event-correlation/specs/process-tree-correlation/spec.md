## ADDED Requirements

### Requirement: Composite Key Identification
The system SHALL identify every process uniquely across the fleet using a composite key in the format `machine|pid`.

#### Scenario: Same PID on different machines
- **WHEN** Event 4688 is ingested from Machine A and Machine B with PID 1234
- **THEN** they are treated as distinct processes `MachineA|1234` and `MachineB|1234`

### Requirement: PID Reuse Resolution
The system SHALL resolve parent-child lineage by selecting the parent candidate with the `birth_time` that is closest but prior to the child process's `birth_time`.

#### Scenario: PID is reused quickly
- **WHEN** a new process is created and multiple prior processes share its `ParentProcessId`
- **THEN** the analyzer links it to the one whose `birth_time` immediately precedes the child's `birth_time`

### Requirement: Log Gap Awareness
The system SHALL track `EventRecordId` gaps to annotate orphan processes.

#### Scenario: Missing 4688 events
- **WHEN** a process has no parent in the window and a log sequence gap is detected
- **THEN** the orphan node is flagged with a warning rather than treated as an anomaly
