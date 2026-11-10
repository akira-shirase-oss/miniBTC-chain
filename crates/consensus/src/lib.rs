//! # minibtc-consensus
//!
//! Every rule that decides whether a transaction or block is valid. **Pure**:
//! no network, no disk, no system clock, no floating point, checked arithmetic
//! everywhere. If two nodes ever disagree on validity the network splits —
//! purity is what makes consensus testable and deterministic.

// Phase scaffold: modules land with their build phase (see docs/ROADMAP.md).
