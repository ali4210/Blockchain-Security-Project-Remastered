pragma circom 2.0.0;

// Section G (EduQual L6 Topic 124) -- real, minimal Groth16 ZK compliance
// circuit. Proves "this address was checked against the OFAC SDN snapshot and
// is NOT flagged" WITHOUT revealing the address: `address` is a PRIVATE input,
// `flaggedHashes` (Poseidon hashes of real, genuine OFAC SDN entries -- see
// generate-sample.js for exactly which real entries) is PUBLIC.
//
// HONEST SCOPE NOTE: this is a real, working minimal ZK circuit demonstrating
// the compliance-privacy PATTERN, not a production-scale compliance ZK system.
// It checks against a fixed set of N=8 real flagged-address hashes (equality
// checks, not a Merkle-tree non-membership proof over the full 506-address
// snapshot) -- large-N set non-membership would use a sorted Merkle tree with
// a neighbour proof instead; N=8 keeps this genuinely real and genuinely small.
//
// The circuit has NO output signal for "clean" -- the hard constraint
// `notFlagged[n] === 1` means a valid witness (and therefore a valid proof)
// can only be COMPUTED for an address that matches none of the flagged
// hashes. For a flagged address, witness generation itself fails: there is no
// such thing as "a proof that says clean=0" here, by design, matching the
// task's framing of "prove X is NOT flagged", not "compute whether X is flagged".

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";

template OfacCleanProof(n) {
    signal input address;             // PRIVATE: the address being checked
    signal input flaggedHashes[n];    // PUBLIC: Poseidon hashes of real flagged addresses

    component hasher = Poseidon(1);
    hasher.inputs[0] <== address;

    component isEq[n];
    signal notFlagged[n + 1];
    notFlagged[0] <== 1;
    for (var i = 0; i < n; i++) {
        isEq[i] = IsZero();
        isEq[i].in <== hasher.out - flaggedHashes[i];
        // isEq[i].out == 1 means a MATCH against flagged entry i (i.e. flagged)
        notFlagged[i + 1] <== notFlagged[i] * (1 - isEq[i].out);
    }
    notFlagged[n] === 1; // hard constraint: must match NONE of the flagged hashes
}

component main {public [flaggedHashes]} = OfacCleanProof(8);
