// Package shared holds the wire-protocol contract between the client and
// the server: the part/ack structures, chunking and reassembly, full-write
// socket IO, and request signing/verification. Keeping these in one place
// keeps both sides of the protocol in lockstep.
package shared

// Part is the single self-describing unit of transfer in both directions.
// Upstream it rides inside a POST batch; downstream it is one NDJSON line.
// Because every part carries its request/seq/part coordinates, sequences may
// be fired and delivered out of order and be reassembled at the destination.
type Part struct {
	ClientID   string `json:"client_id,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
	Seq        int    `json:"seq"`
	Part       int    `json:"part"`
	TotalParts int    `json:"total_parts"`
	Data       string `json:"data,omitempty"`
	Final      bool   `json:"final,omitempty"`
}

// AckPayload is the upload response. Acked is one '0'/'1' bit per uploaded
// part, in batch order: '1' means the server accepted the part (buffered,
// duplicate of already-flushed data, or final marker); '0' means it must be
// retried. Downstream, when present, piggybacks queued downstream parts on
// the response — a second delivery lane alongside the /poll stream.
type AckPayload struct {
	Acked      string `json:"acked"`
	Downstream []Part `json:"downstream,omitempty"`
}

// PostBatch is the upload request body: parts gathered by the client's
// dispatcher workers, totalling at most ~16KB of marshalled payload.
type PostBatch struct {
	Parts []Part `json:"parts"`
}
