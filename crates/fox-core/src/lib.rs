//! FOX Core - Evidence System, Error Types, and Foundational Abstractions
//!
//! The Evidence System is the most important engineering requirement of FOX.
//! Every analysis result MUST be traceable to concrete evidence.
//! No analysis result may be asserted without supporting evidence.

pub mod address;
pub mod edge;
pub mod error;
pub mod evidence;
pub mod identity;
pub mod result;

pub use address::Address;
pub use edge::{CallEdgeKind, CallGraphEdge, CfgEdge, EdgeKind, IndirectCallKind};
pub use error::FoxError;
pub use evidence::{
    adjudicate_reality, BodyReality, BoundaryReality, ClaimContradiction, ClaimStrength,
    ClaimSubject, ClaimType, Confidence, Evidence, EvidenceClaim, EvidenceKind, EvidenceList,
    FunctionRange, FunctionReality, IdentityReality, RealityStatus, WithEvidence,
};
pub use result::FoxResult;
