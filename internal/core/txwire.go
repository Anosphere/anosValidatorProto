package core

import (
	"google.golang.org/protobuf/proto"

	pb "anos/internal/proto"
)

// CanonicalTxBytes returns the canonical wire bytes for a Tx.
//
// Why:
// - The engine treats "raw tx bytes" as canonical everywhere (DB/gossip/apply).
// - We must ensure all internal conversions pb.Tx -> []byte produce a single stable format.
//
// We use deterministic protobuf marshaling so that the same Tx always produces identical bytes.
func CanonicalTxBytes(tx *pb.Tx) ([]byte, error) {
	return (proto.MarshalOptions{Deterministic: true}).Marshal(tx)
}
