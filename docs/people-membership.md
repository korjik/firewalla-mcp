# People and device membership

`people_and_devices` is deployed in inventory-v1 with the reviewed helper trust gate. It does not infer membership from a device name.
Public source reviewed at revision `173ac36dccb5239a5195a5b4e64d20cb1b618a91`
and installed source on both tested platforms establish:

| Kind | Active set | Metadata hash prefix | Device/tag policy field |
|---|---|---|---|
| People (`user`) | `tag:user:active` | `userTag:uid:` | `userTags` |
| Regular groups | `tag:group:active` | `tag:uid:` | `tags` |
| Device tags | `tag:device:active` | `deviceTag:uid:` | `deviceTags` |
| SSID tags | `tag:ssid:active` | `ssidTag:uid:` | `ssidTags` |

Catalogs are enumerated independently of devices to preserve empty entries.
The collector reads only name/bname and the four membership fields from host,
`policy:mac:` and `policy:tag:` records. Explicit tag-to-tag relationships matter:
a device tag can assign a device to a Person even when host userTags is absent.
Traversal detects cycles and limits depth to 16. It deduplicates devices across
multiple paths; derived membership carries an explicit relationship basis.
There is no full init, full hash, traffic history, or credential API call.

One bounded read-only Redis script provides a consistent selected-field snapshot.
It scans at most 1024 iterations with COUNT 256, at most 1024 distinct hosts and
256 tags, and at most 90 KB selected field bytes. SCAN completion alone determines
completeness; empty intermediate pages are not terminal. Oversized snapshots fail
closed. A partial scan or unresolved tag yields unknown assigned counts, not zero.
The server caps a returned directory at 120 KB and recommends selecting a person
when larger. Names are untrusted display metadata.

Counts refer to distinct stored MAC records, including retained offline records;
app display counts may use a different grouping or retention view. No screenshot
count is hardcoded or treated as current truth. A complete empty Person has zero
explicit assignments; a similarly named unassigned device is listed separately
as a name match, never as ownership. The collector was read-tested on both
platforms, and the new tool passed backend MCP and ContextForge invocation tests.
