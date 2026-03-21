## ADDED Requirements

### Requirement: Strict PID Search
The system SHALL support filtering the event graph strictly by Process ID exact match.

#### Scenario: User searches for exact PID
- **WHEN** user inputs a strict PID query utilizing the designated prefix (e.g. `pid:1234`)
- **THEN** the system only displays or matches nodes where the `pid` field strictly equals the input
- **AND** ignores false positive partial matches across `command_line`, `object_name`, or alternative entity names.
