## Why
Currently, the search function uses a generic `.includes()` match across multiple fields (PID, names, Command Line). This causes many false positives when users solely want to locate a specific Process ID (e.g., searching for PID `1234` matches any command line containing `1234`). A strict PID-only search mode is needed to streamline hunting specific execution paths without the noise of accidental string matches.

## What Changes
- Add a strict matching mechanism in the frontend specifically for PID lookup.
- Introduced a prefix syntax `pid:` (e.g., `pid:1234`) which tells the filter to strictly check `n.pid == 1234` and bypass general string matching for command lines and object names.

## Capabilities

### New Capabilities
- `pid-search`: Strict exact-match search for PID fields specifically.

### Modified Capabilities

## Impact
- `threatgraph/static/js/app.js` UI search rendering logic will be modified. No backend changes required.
