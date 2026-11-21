package approve

import (
	"context"
	"errors"
	"testing"
	"time"

	"gatelock/internal/vault"
)

// waiting asks and waits for no answer, closing withdrawn once withdrawn.
func waiting(withdrawn chan struct{}) Ask {
	return func(ctx context.Context) error {
		<-ctx.Done()
		close(withdrawn)
		return ctx.Err()
	}
}

func answering(err error) Ask {
	return func(context.Context) error { return err }
}

func TestFirstAnswerWinsAndWithdrawsTheRest(t *testing.T) {
	for _, answer := range []error{nil, &vault.DeniedError{By: "Telegram", Reason: "no"}} {
		withdrawn := make(chan struct{})
		err := First(context.Background(), waiting(withdrawn), answering(answer))
		if err != answer {
			t.Fatalf("got %v, want %v", err, answer)
		}
		select {
		case <-withdrawn:
		default:
			t.Fatal("returned before the other question was withdrawn")
		}
	}
}

func TestFailureToAskIsNoAnswer(t *testing.T) {
	failed := errors.New("Touch ID: canceled by the system")
	slow := func(context.Context) error {
		time.Sleep(20 * time.Millisecond)
		return &vault.DeniedError{Reason: "later"}
	}
	err := First(context.Background(), answering(failed), slow)
	var denied *vault.DeniedError
	if !errors.As(err, &denied) || denied.Reason != "later" {
		t.Fatalf("got %v", err)
	}
}

func TestAllFailing(t *testing.T) {
	a, b := errors.New("a"), errors.New("b")
	err := First(context.Background(), answering(a), answering(b))
	if !errors.Is(err, a) || !errors.Is(err, b) || errors.Is(err, vault.ErrDenied) {
		t.Fatalf("got %v", err)
	}
	if err := First(context.Background()); err == nil {
		t.Fatal("no error asking nowhere")
	}
}

func TestCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	withdrawn := make(chan struct{})
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	if err := First(ctx, waiting(withdrawn), answering(errors.New("could not ask"))); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}
