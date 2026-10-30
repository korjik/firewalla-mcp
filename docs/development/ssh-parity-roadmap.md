# SSH feature roadmap

The [amittell reference](https://github.com/amittell/firewalla-mcp-server/tree/46a15cb6e82f391b44608120b5f37ba84771a33f) uses MSP APIs. Its tool catalog is useful for feature comparison, not proof of an equivalent local SSH contract. This project has no MSP dependency and does not copy its adapters. See [licensing and related projects](related-projects.md) and the authoritative [support matrix](../features.md).

Useful remaining work, subject to separate source/contract review:

- Richer bounded device search/offline views and target-list metadata.
- Active and archived alarm detail/search with selected fields only.
- General flow search and aggregates with explicit retention, sampling and pagination limits; never reconstruct missing history as zero.
- Region/bandwidth/trend summaries only where trustworthy local data supports the requested interval.
- Hardware-gated AP/channel/SSID diagnostics, without assuming all boxes expose them.
- Individual persistent rule edit/pause/resume/delete, device rename, alarm archive/delete/mute and target-list write contracts. A common approval manager does not implement these operations. Alarm muting is not firewall allowlisting.

MSP account/fleet semantics, cloud-owned lists and long-term cloud history may have no equivalent local adapter. Do not add invented subnets, derive present enforcement from a historical flow, or promise full feature parity based on matching tool names/counts.

Future prompt/resource guides can help users investigate security, bandwidth, devices and network health, but should call supported tools, distinguish evidence from inference and disclose incomplete data. Source checks, tests and safe state/approval handling precede any new write capability. Upstream appliance source has separate licensing; do not vendor it into this MIT project without review.
