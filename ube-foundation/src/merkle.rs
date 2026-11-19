//! RFC 6962 Merkle Tree Hash for the audit trail.
//!
//! The audit batch root commits to the ordered event hashes. Two properties
//! matter for a security audit trail:
//!
//! * **Domain separation.** Leaves and interior nodes are hashed with distinct
//!   prefixes. Without them a second-preimage attack can present an interior
//!   node as a leaf. The prefixes are the project's documented ones
//!   (`nti-s5-leaf-v1:` / `nti-s5-node-v1:`), not RFC 6962's raw `0x00`/`0x01`,
//!   so a Rust audit root and the conformance witness generator agree byte for
//!   byte. See `conformance/witness/README.md`.
//! * **Odd-node promotion.** On an odd level the last node is carried up
//!   unchanged, never duplicated (RFC 6962 §2.1). Duplicating it makes the tree
//!   for `n` leaves collide with the tree for `n + 1` leaves, so a proof for one
//!   batch verifies against another.
//!
//! Leaves are the hex-encoded SHA-256 hashes of the audit events themselves, so
//! the root binds the event contents transitively.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Leaf prefix for the audit / S5 evidence root.
pub const DOMAIN_LEAF: &[u8] = b"nti-s5-leaf-v1:";
/// Interior-node prefix for the audit / S5 evidence root.
pub const DOMAIN_NODE: &[u8] = b"nti-s5-node-v1:";

/// A leaf/node prefix pair for one Merkle context.
///
/// Prefixes are per-context so a proof built for one tree cannot be replayed
/// against a root of a different kind, even when both use the same hash.
#[derive(Debug, Clone, Copy)]
pub struct MerkleDomain {
    /// Prefix for leaf hashes.
    pub leaf: &'static [u8],
    /// Prefix for interior-node hashes.
    pub node: &'static [u8],
}

/// The audit-trail domain, matching the conformance witness generator.
pub const AUDIT_DOMAIN: MerkleDomain = MerkleDomain {
    leaf: DOMAIN_LEAF,
    node: DOMAIN_NODE,
};

/// Position of a sibling relative to the node it is folded with.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MerkleSiblingPosition {
    /// The sibling is the left child.
    Left,
    /// The sibling is the right child.
    Right,
    /// The accumulator was the odd node on this level and was promoted.
    Promoted,
}

/// One step of a Merkle inclusion proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleSibling {
    /// Where the sibling sits relative to the accumulator.
    pub position: MerkleSiblingPosition,
    /// Hex-encoded sibling hash.
    pub sha256: String,
}

/// Decodes a 64-character hex SHA-256 digest.
fn decode_digest(hex_digest: &str) -> Option<[u8; 32]> {
    if hex_digest.len() != 64 {
        return None;
    }
    hex::decode(hex_digest).ok()?.try_into().ok()
}

/// Leaf hash of an event digest under `domain`.
pub fn leaf_hash_in(domain: MerkleDomain, event_hash_hex: &str) -> Option<String> {
    let digest = decode_digest(event_hash_hex)?;
    let mut hasher = Sha256::new();
    hasher.update(domain.leaf);
    hasher.update(digest);
    Some(hex::encode(hasher.finalize()))
}

/// Interior-node hash under `domain`.
fn node_hash_in(domain: MerkleDomain, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain.node);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Builds one level up, promoting an unpaired trailing node unchanged.
fn next_level(domain: MerkleDomain, level: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    let mut index = 0;
    while index + 1 < level.len() {
        next.push(node_hash_in(domain, &level[index], &level[index + 1]));
        index += 2;
    }
    if index < level.len() {
        next.push(level[index]);
    }
    next
}

fn leaf_level(domain: MerkleDomain, leaves: &[String]) -> Option<Vec<[u8; 32]>> {
    if leaves.is_empty() {
        return None;
    }
    leaves
        .iter()
        .map(|leaf| decode_digest(&leaf_hash_in(domain, leaf)?))
        .collect()
}

/// Merkle root over the ordered leaf digests in the audit domain.
pub fn merkle_root(leaves: &[String]) -> Option<String> {
    merkle_root_in(AUDIT_DOMAIN, leaves)
}

/// Merkle root over the ordered leaf digests under `domain`.
///
/// Returns `None` for an empty tree or a malformed leaf, so callers fail closed
/// instead of committing to a root that cannot be recomputed.
pub fn merkle_root_in(domain: MerkleDomain, leaves: &[String]) -> Option<String> {
    let mut level = leaf_level(domain, leaves)?;
    while level.len() > 1 {
        level = next_level(domain, &level);
    }
    Some(hex::encode(level[0]))
}

/// Inclusion proof for the leaf at `index` in the audit domain.
pub fn inclusion_proof(leaves: &[String], index: usize) -> Option<Vec<MerkleSibling>> {
    inclusion_proof_in(AUDIT_DOMAIN, leaves, index)
}

/// Inclusion proof for the leaf at `index` under `domain`.
pub fn inclusion_proof_in(
    domain: MerkleDomain,
    leaves: &[String],
    index: usize,
) -> Option<Vec<MerkleSibling>> {
    let mut level = leaf_level(domain, leaves)?;
    if index >= level.len() {
        return None;
    }

    let mut proof = Vec::new();
    let mut cursor = index;
    while level.len() > 1 {
        if cursor % 2 == 1 {
            proof.push(MerkleSibling {
                position: MerkleSiblingPosition::Left,
                sha256: hex::encode(level[cursor - 1]),
            });
        } else if cursor + 1 < level.len() {
            proof.push(MerkleSibling {
                position: MerkleSiblingPosition::Right,
                sha256: hex::encode(level[cursor + 1]),
            });
        } else {
            // Unpaired tail: this node is promoted unchanged.
            proof.push(MerkleSibling {
                position: MerkleSiblingPosition::Promoted,
                sha256: hex::encode(level[cursor]),
            });
        }
        level = next_level(domain, &level);
        cursor /= 2;
    }
    Some(proof)
}

/// Folds an inclusion proof for `leaf` into a candidate root in the audit
/// domain and compares it with `root` in constant time.
pub fn verify_inclusion(leaf: &str, proof: &[MerkleSibling], root: &str) -> bool {
    verify_inclusion_in(AUDIT_DOMAIN, leaf, proof, root)
}

/// Folds an inclusion proof for `leaf` under `domain` and compares the result
/// with `root` in constant time.
pub fn verify_inclusion_in(
    domain: MerkleDomain,
    leaf: &str,
    proof: &[MerkleSibling],
    root: &str,
) -> bool {
    use subtle::ConstantTimeEq;

    let Some(leaf_hash_hex) = leaf_hash_in(domain, leaf) else {
        return false;
    };
    let Some(mut accumulator) = decode_digest(&leaf_hash_hex) else {
        return false;
    };

    for sibling in proof {
        let Some(digest) = decode_digest(&sibling.sha256) else {
            return false;
        };
        accumulator = match sibling.position {
            MerkleSiblingPosition::Left => node_hash_in(domain, &digest, &accumulator),
            MerkleSiblingPosition::Right => node_hash_in(domain, &accumulator, &digest),
            MerkleSiblingPosition::Promoted => {
                if digest.ct_eq(&accumulator).unwrap_u8() != 1 {
                    return false;
                }
                accumulator
            }
        };
    }

    let Some(expected) = decode_digest(root) else {
        return false;
    };
    accumulator.ct_eq(&expected).unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent reference implementation of RFC 6962 §2.1 MTH, split at the
    /// largest power of two below the leaf count rather than iteratively.
    fn reference_mth(domain: MerkleDomain, leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.len() == 1 {
            let mut hasher = Sha256::new();
            hasher.update(domain.leaf);
            hasher.update(leaves[0]);
            return hasher.finalize().into();
        }
        let mut k = 1;
        while k * 2 < leaves.len() {
            k *= 2;
        }
        let left = reference_mth(domain, &leaves[..k]);
        let right = reference_mth(domain, &leaves[k..]);
        node_hash_in(domain, &left, &right)
    }

    fn digests(count: usize) -> Vec<[u8; 32]> {
        (0..count)
            .map(|i| Sha256::digest(format!("event-{i}").as_bytes()).into())
            .collect()
    }

    fn hex_leaves(count: usize) -> Vec<String> {
        digests(count).iter().map(hex::encode).collect()
    }

    #[test]
    fn root_matches_reference_implementation() {
        for count in 1..=9 {
            let leaves = hex_leaves(count);
            let expected = hex::encode(reference_mth(AUDIT_DOMAIN, &digests(count)));
            assert_eq!(merkle_root(&leaves), Some(expected), "leaf count {count}");
        }
    }

    /// Cross-implementation check: the pinned S5 root from the conformance
    /// witness package must be reproducible here, or the Rust audit root and the
    /// witness generator would disagree about the same evidence.
    #[test]
    fn root_matches_pinned_conformance_vector() {
        let leaves = [
            "9b1f86ec9a8edc1635b0a6df4b1630ca98670a2be1967ba76394aae47e59c633",
            "f1990a7f9652b6bb5a9b6f708d7dd5d22a62a34e2b8229389cf2973bbef6f6e0",
            "07ca9b5aa9b9900badb3bad7ff0055e76695b6a3e6f020e084c6c8d2ed30a16c",
            "b71f313d5b7dcffca09c0838e4e46e90038c4bc85b234b87143bd88e0052cfdc",
        ];

        // These are already domain-separated leaf digests, so the tree is built
        // over them directly with the node prefix.
        let mut level: Vec<[u8; 32]> = leaves.iter().map(|l| decode_digest(l).unwrap()).collect();
        while level.len() > 1 {
            level = next_level(AUDIT_DOMAIN, &level);
        }
        assert_eq!(
            hex::encode(level[0]),
            "20271a5928932d6362ff566207e20f60cb2a5e387a7178dbf6da028d7c01fe1e"
        );
    }

    #[test]
    fn odd_node_is_promoted_not_duplicated() {
        let three = hex_leaves(3);
        let mut four = three.clone();
        four.push(three[2].clone());
        assert_ne!(merkle_root(&three), merkle_root(&four));
    }

    #[test]
    fn inclusion_proofs_verify_for_every_index() {
        for count in 1..=9 {
            let leaves = hex_leaves(count);
            let root = merkle_root(&leaves).unwrap();
            for index in 0..count {
                let proof = inclusion_proof(&leaves, index).unwrap();
                assert!(
                    verify_inclusion(&leaves[index], &proof, &root),
                    "leaf {index} of {count}"
                );
            }
        }
    }

    #[test]
    fn tampered_proofs_and_leaves_are_rejected() {
        let leaves = hex_leaves(5);
        let root = merkle_root(&leaves).unwrap();
        let proof = inclusion_proof(&leaves, 1).unwrap();

        assert!(!verify_inclusion(&leaves[2], &proof, &root));

        let mut forged = proof.clone();
        forged[0].sha256 = hex_leaves(9)[8].clone();
        assert!(!verify_inclusion(&leaves[1], &forged, &root));

        let mut promoted = proof.clone();
        promoted.push(MerkleSibling {
            position: MerkleSiblingPosition::Promoted,
            sha256: "00".repeat(32),
        });
        assert!(!verify_inclusion(&leaves[1], &promoted, &root));
    }

    #[test]
    fn empty_and_malformed_trees_fail_closed() {
        assert_eq!(merkle_root(&[]), None);
        assert_eq!(merkle_root(&["not-a-digest".to_string()]), None);
        assert_eq!(inclusion_proof(&[], 0), None);
        assert_eq!(inclusion_proof(&hex_leaves(2), 2), None);
        assert!(!verify_inclusion(&"zz".repeat(32), &[], &"00".repeat(32)));
    }

    #[test]
    fn proofs_do_not_verify_across_domains() {
        const OTHER: MerkleDomain = MerkleDomain {
            leaf: b"nti-delegation-leaf-v1:",
            node: b"nti-delegation-node-v1:",
        };
        let leaves = hex_leaves(4);
        let audit_root = merkle_root_in(AUDIT_DOMAIN, &leaves).unwrap();
        let audit_proof = inclusion_proof_in(AUDIT_DOMAIN, &leaves, 0).unwrap();

        assert!(!verify_inclusion_in(
            OTHER,
            &leaves[0],
            &audit_proof,
            &audit_root
        ));
        assert_ne!(merkle_root_in(OTHER, &leaves).unwrap(), audit_root);
    }
}
