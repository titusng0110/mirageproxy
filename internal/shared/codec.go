package shared

import (
	"encoding/base64"
	"strings"
)

// Chunk base64-encodes data and splits the encoded string into chunks of at
// most chunkSize characters. The chunks cover the payload in order and the
// last one carries the remainder. chunkSize must be at least 1.
func Chunk(data []byte, chunkSize int) []string {
	encoded := base64.StdEncoding.EncodeToString(data)
	total := (len(encoded) + chunkSize - 1) / chunkSize
	chunks := make([]string, total)
	for i := 0; i < total; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(encoded) {
			end = len(encoded)
		}
		chunks[i] = encoded[start:end]
	}
	return chunks
}

// Assemble concatenates parts 1..total in order and base64-decodes the
// result. It is the inverse of Chunk.
func Assemble(parts map[int]string, total int) ([]byte, error) {
	var combined strings.Builder
	for i := 1; i <= total; i++ {
		combined.WriteString(parts[i])
	}
	return base64.StdEncoding.DecodeString(combined.String())
}
