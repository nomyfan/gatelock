// Package macauth asks the person at the Mac to approve, with Touch ID or
// their login password, through LocalAuthentication.
package macauth

import (
	"context"
	"fmt"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"

	"gatelock/internal/vault"
)

// LAPolicyDeviceOwnerAuthentication: Touch ID, or the login password.
const policyDeviceOwnerAuthentication = 2

// The LAError codes for the user not approving.
const (
	errAuthenticationFailed = -1
	errUserCancel           = -2
	errSystemCancel         = -4
)

var loadOnce = sync.OnceValue(func() error {
	for _, fw := range []string{
		"/System/Library/Frameworks/Foundation.framework/Foundation",
		"/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication",
	} {
		if _, err := purego.Dlopen(fw, purego.RTLD_GLOBAL|purego.RTLD_NOW); err != nil {
			return err
		}
	}
	return nil
})

// ConfirmUser asks the user to approve, showing reason. It returns nil if
// they do, an error wrapping vault.ErrDenied if they do not, and ctx's
// error, dismissing the question, if ctx is done first.
func ConfirmUser(ctx context.Context, reason string) error {
	if err := loadOnce(); err != nil {
		return err
	}
	la := objc.ID(objc.GetClass("LAContext")).Send(objc.RegisterName("new"))
	defer la.Send(objc.RegisterName("release"))

	type reply struct {
		ok   bool
		code int
		desc string
	}
	replies := make(chan reply, 1)
	blk := objc.NewBlock(func(_ objc.Block, ok bool, err objc.ID) {
		r := reply{ok: ok}
		if !ok {
			r.code = objc.Send[int](err, objc.RegisterName("code"))
			r.desc = goString(err.Send(objc.RegisterName("localizedDescription")))
		}
		replies <- r
	})
	defer blk.Release()

	str := objc.ID(objc.GetClass("NSString")).Send(objc.RegisterName("stringWithUTF8String:"), reason)
	la.Send(objc.RegisterName("evaluatePolicy:localizedReason:reply:"), policyDeviceOwnerAuthentication, str, blk)

	var r reply
	select {
	case r = <-replies:
	case <-ctx.Done():
		la.Send(objc.RegisterName("invalidate"))
		<-replies
		return ctx.Err()
	}
	switch {
	case r.ok:
		return nil
	case r.code == errUserCancel || r.code == errAuthenticationFailed || r.code == errSystemCancel:
		return fmt.Errorf("%w: %s", vault.ErrDenied, r.desc)
	default:
		return fmt.Errorf("authentication failed (%d): %s", r.code, r.desc)
	}
}

func goString(nsString objc.ID) string {
	p := objc.Send[*byte](nsString, objc.RegisterName("UTF8String"))
	if p == nil {
		return ""
	}
	n := 0
	for *(*byte)(unsafe.Add(unsafe.Pointer(p), n)) != 0 {
		n++
	}
	return string(unsafe.Slice(p, n))
}
