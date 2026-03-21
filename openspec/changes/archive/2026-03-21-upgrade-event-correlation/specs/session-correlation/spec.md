## ADDED Requirements

### Requirement: Logon Scope Identification
The system SHALL link process trees and events to a user session using the `machine|logon_id` composite key.

#### Scenario: Grouping actions by session
- **WHEN** an analyst queries actions by a user
- **THEN** all processes sharing the same `logon_scope` are retrieved together

### Requirement: Token Impersonation Detection
The system SHALL detect token impersonation when an event's `SubjectLogonId` differs from its host process's `logon_scope`.

#### Scenario: Thread impersonates another user
- **WHEN** a file access event's `logon_scope` does not match the process `logon_scope`
- **THEN** the system flags `logonid_mismatch` and distinguishes `effective_user` from `process_owner`
