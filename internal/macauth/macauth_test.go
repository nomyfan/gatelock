package macauth

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// These show the system's authentication dialog, so they run only when
// asked: GATELOCK_DIALOG_TESTS=1 go test ./internal/macauth -v

func TestCanceledContextDismissesDialog(t *testing.T) {
	if os.Getenv("GATELOCK_DIALOG_TESTS") == "" {
		t.Skip("shows a dialog")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := ConfirmUser(ctx, "test that a dismissed question returns"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

func TestAnswer(t *testing.T) {
	if os.Getenv("GATELOCK_DIALOG_TESTS") == "" {
		t.Skip("shows a dialog")
	}
	t.Logf("approve or cancel the dialog; got %v", ConfirmUser(context.Background(), "test approving or canceling"))
}
