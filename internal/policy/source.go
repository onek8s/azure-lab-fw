package policy

import (
	"context"
)

// Source fetches a policy bundle. Implementations: FileSource (here) and the
// ARM source (internal/azure, W7). Parse warnings are returned in
// Bundle.Warnings.
type Source interface {
	Fetch(ctx context.Context) (*Bundle, error)
}

// FileSource reads a bundle file (policy.source: file).
type FileSource struct {
	Path string
}

// NewFileSource returns a Source reading the bundle at path on every Fetch.
func NewFileSource(path string) *FileSource { return &FileSource{Path: path} }

// Fetch implements Source.
func (s *FileSource) Fetch(ctx context.Context) (*Bundle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, _, err := LoadFile(s.Path)
	return b, err
}

var _ Source = (*FileSource)(nil)
