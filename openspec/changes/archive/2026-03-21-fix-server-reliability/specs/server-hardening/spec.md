## ADDED Requirements

### Requirement: Task ID Validation
The system SHALL validate the `task_id` to prevent directory traversal attacks.

#### Scenario: Malicious task ID is provided
- **WHEN** a client provides a `task_id` containing slashes or dots (e.g., `../file`) or an invalid extension
- **THEN** the server rejects the request with a 404 or 400 error immediately

### Requirement: Resource Cleanup on Upload Failure
The system SHALL ensure that partial or failed temporary uploads are deleted.

#### Scenario: Upload fails mid-stream
- **WHEN** an exception is raised while reading the `UploadFile` chunks
- **THEN** the temporary file is unlinked from the filesystem before returning an error

### Requirement: Reliable Browser Launch
The system SHALL wait for the HTTP server to become responsive before opening the web browser.

#### Scenario: Server start is delayed
- **WHEN** `uvicorn` takes longer than expected to bind the port
- **THEN** the auto-open thread polls the address until successful (up to a timeout limit), ensuring the user sees the page and not an error
