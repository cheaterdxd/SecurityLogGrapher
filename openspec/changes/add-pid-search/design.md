## Approach
We will modify the `matchNode(n, t)` function in `threatgraph/static/js/app.js`.
If the user's input string `t` starts with `pid:` (for example, `pid:1234`), the function will precisely extract the numeric portion and strictly compare it against `n.pid`. If it matches, it guarantees the node matches; otherwise, it rejects it immediately to prevent false positives in `command_line` or `label`.
If the input lacks the prefix, it falls back to the existing broad string-matching.

## Alternatives Considered
- Checking if `t` is entirely numeric (`!isNaN(t)`). If yes, only search PIDs. However, some legitimate file/registry paths contain plain numbers, so an explicit prefix `pid:` is a more robust, intentional, and flexible UX choice.

## Data Model & APIs
No changes to backend API or data model. This is purely a frontend Javascript string matching enhancement affecting the left-panel tree explorer.

## Security & Privacy
N/A
