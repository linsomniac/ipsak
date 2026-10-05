package localnet

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestCommandOutputCopyRemainsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &limitedBuffer{Limit: 8192, Cancel: cancel}
	_, err := io.Copy(b, struct{ io.Reader }{strings.NewReader(strings.Repeat("x", 10000))})
	if err == nil || !b.Overflow || b.buffer.Len() > b.Limit || ctx.Err() == nil {
		t.Fatalf("error=%v overflow=%v size=%d canceled=%v", err, b.Overflow, b.buffer.Len(), ctx.Err())
	}
}
