# Roadmap

This roadmap outlines potential future work for GhostChat. It is intentionally scoped as a research and portfolio project; items here describe how it could be hardened or extended, not promises for a production deployment.

---

## Short-term improvements

- **Stronger replay tracking**
  - Review and harden replay cache policies for both pairwise and group messaging.
  - Consider additional metadata (e.g., epoch numbers or rolling window bounds) in replay keys to reduce edge cases.
  - Add more stress tests for high-volume or bursty traffic patterns to catch replay-related regressions.

- **Better relay queue handling**
  - Integrate `server/memory_mailbox.MemoryMailboxStore` more tightly with the router used in tests.
  - Add explicit TTL configuration and observability (e.g., metrics on dropped vs delivered envelopes).
  - Improve error handling around malformed envelopes and mailbox operations, ensuring failures are visible but do not crash the relay.

These items mostly refine the existing design and strengthen the invariants already documented.

---

## Medium-term improvements

- **Real mixnet-style routing**
  - Generalize the `MixRouter` into a multi-hop abstraction, allowing envelopes to pass through multiple relay nodes with independent delay and batching parameters.
  - Implement basic path selection and per-hop encryption (on top of sealed sender) for lab-scale experiments.
  - Add tests and metrics to evaluate latency, throughput, and basic anonymity properties in small topologies.

- **Stronger anonymity set**
  - Increase and tune cover traffic rates so that active and idle periods look more similar from the relay’s point of view.
  - Explore simple padding strategies to normalize envelope sizes across different message types.
  - Study how small-group usage patterns affect anonymity and adjust mix/cover parameters accordingly.

These changes move GhostChat from “metadata hardening” toward a more principled anonymity story, while remaining honest about limits.

---

## Long-term improvements

- **MLS compliance**
  - Replace the simplified MLS-inspired group layer with a spec-compliant MLS implementation.
  - Support MLS proposals and commits, authenticated transcripts, and more dynamic group sizes.
  - Ensure that epoch transitions, membership changes, and security properties align with the official MLS specification.

- **Multi-device identity**
  - Extend the identity and prekey model to handle multiple devices per user, with per-device signed prekeys and session management.
  - Clarify how sessions are established, rotated, and retired across devices without breaking forward secrecy or PCS.
  - Address replay and fork handling in the presence of multiple concurrent devices.

- **Formal protocol verification**
  - Model key parts of the protocol (handshake, ratchet, group epochs) in a tool such as Tamarin or ProVerif.
  - Prove or falsify properties like forward secrecy, authentication, and confidentiality under the documented threat model.
  - Use results to refine both the implementation and the documentation (e.g., invariants and attack surface analysis).

These long-term items move GhostChat from a teaching prototype toward something that could be used as the basis for a production-grade secure messaging system.

