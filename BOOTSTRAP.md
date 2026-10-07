# Bootstrap brief for the remote-workplace orchestrator
Own this project: write the **security protocol** for remote workers and a **minimal reference workplace** that remote-worker-harness can adopt.
Read README.md and docs/design-brief.md first; they are the agreed starting point.
The owner's rule is simple and reliable over clever. Keep one strong boundary (the container in a no-home colima profile) and cut anything that does not clearly earn its place.
Deliverables, in order: (1) docs/protocol.md, a short normative spec: what a worker may do, the workplace's guarantees, the change-extraction path, network policy, and what the harness must do;
(2) a Go tool that creates/destroys the per-worker container and runs a tool call inside it (the harness calls it); (3) the red-team suite with positive controls; (4) integration notes for remote-worker-harness.
