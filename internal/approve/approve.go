// Package approve asks the user in several places at once, such as Touch
// ID at the Mac and a chat on their phone, and takes the first answer.
package approve

import (
	"context"
	"errors"

	"gatelock/internal/vault"
)

// Ask asks the user in one place. It returns nil if they approve, an error
// wrapping vault.ErrDenied if they deny, ctx's error once ctx is done, and
// any other error if it could not ask, which is no answer.
type Ask func(ctx context.Context) error

// First asks in each place at once. The first answer, approving or
// denying, is the answer, and the questions still open are withdrawn:
// First returns once each Ask has. A place that fails to ask is passed
// over; if every one does, First returns their errors, or ctx's error if
// it is done.
func First(ctx context.Context, asks ...Ask) error {
	if len(asks) == 0 {
		return errors.New("nowhere to ask")
	}
	asking, withdraw := context.WithCancel(ctx)
	defer withdraw()
	results := make(chan error, len(asks))
	for _, ask := range asks {
		go func() { results <- ask(asking) }()
	}
	var answer error
	answered := false
	var failures []error
	for range asks {
		err := <-results
		switch {
		case answered:
			// Withdrawn, or answered too late.
		case err == nil || errors.Is(err, vault.ErrDenied):
			answer, answered = err, true
			withdraw()
		default:
			failures = append(failures, err)
		}
	}
	if answered {
		return answer
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.Join(failures...)
}
