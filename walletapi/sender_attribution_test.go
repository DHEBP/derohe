package walletapi

// Guards the sender-attribution decision recorded in FINDINGS.md: a received
// transfer is attributed to a ring member ONLY at ring size 2.
//
// Above ring 2 the sender chooses the leading byte of the encrypted payload and
// nothing checks it — consensus never reads it, the proof does not bind it, and
// the one bit the proof does expose (Proof.Parity, the low bit of the sender's
// ring index) is already derivable by the receiver from its own slot. So the
// byte is a claim. This chain does not turn a claim into a displayed sender.
//
// The assertions are made over the AST rather than by grepping, so re-adding the
// attribution inside a comment does not trip the guard and re-adding it for real
// cannot slip past under a different variable name.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

const attributionSourceFile = "daemon_communication.go"

// enclosingRingTwoGuard reports whether any node on the stack is an `if` whose
// condition constrains RingSize to 2.
func enclosingRingTwoGuard(fset *token.FileSet, src []byte, stack []ast.Node) bool {
	for _, n := range stack {
		ifs, ok := n.(*ast.IfStmt)
		if !ok || ifs.Cond == nil {
			continue
		}
		cond := sourceOf(fset, src, ifs.Cond)
		if strings.Contains(cond, "RingSize") && strings.Contains(cond, "2") {
			return true
		}
	}
	return false
}

// originOf resolves the right-hand side of an assignment back to the statement
// that produced it. Given `entry.Sender = addr.String()` it returns the source of
// the nearest enclosing `addr := ...`, so classification is based on what the
// address was built from rather than on neighbouring text.
func originOf(fset *token.FileSet, src []byte, stack []ast.Node, rhs ast.Expr) string {
	base := sourceOf(fset, src, rhs)
	if i := strings.IndexAny(base, ".("); i > 0 {
		base = base[:i]
	}
	if base == "" {
		return sourceOf(fset, src, rhs)
	}

	for i := len(stack) - 1; i >= 0; i-- {
		var list []ast.Stmt
		switch b := stack[i].(type) {
		case *ast.BlockStmt:
			list = b.List
		case *ast.CaseClause:
			list = b.Body
		default:
			continue
		}
		for _, stmt := range list {
			as, ok := stmt.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				continue
			}
			if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Name == base {
				return sourceOf(fset, src, as.Rhs[0])
			}
		}
	}
	return sourceOf(fset, src, rhs)
}

func sourceOf(fset *token.FileSet, src []byte, n ast.Node) string {
	start := fset.Position(n.Pos()).Offset
	end := fset.Position(n.End()).Offset
	if start < 0 || end > len(src) || start > end {
		return ""
	}
	return string(src[start:end])
}

// TestSenderAttributionOnlyAtRingTwo asserts that every address built from a
// ring member for attribution purposes sits under a ring-size-2 guard, while the
// outgoing path — which names the wallet's OWN key and claims nothing — is left
// alone.
func TestSenderAttributionOnlyAtRingTwo(t *testing.T) {
	src, err := os.ReadFile(attributionSourceFile)
	if err != nil {
		t.Fatalf("reading %s: %v", attributionSourceFile, err)
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, attributionSourceFile, src, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", attributionSourceFile, err)
	}

	var (
		guardedRingMemberSites   int
		unguardedRingMemberSites []string
		ownKeySites              int
		stack                    []ast.Node
	)

	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)

		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		if sourceOf(fset, src, assign.Lhs[0]) != "entry.Sender" {
			return true
		}

		// Resolve where the assigned address actually came from, rather than
		// classifying by whatever text happens to share the enclosing block —
		// the outgoing path builds entry.Destination from a ring member two
		// statements later, and that is legitimate.
		origin := originOf(fset, src, stack, assign.Rhs[0])

		switch {
		case strings.Contains(origin, "Publickeylist"):
			if enclosingRingTwoGuard(fset, src, stack) {
				guardedRingMemberSites++
			} else {
				unguardedRingMemberSites = append(unguardedRingMemberSites,
					fset.Position(assign.Pos()).String())
			}
		case strings.Contains(origin, "w.account.Keys.Public"):
			// The outgoing path names the wallet's own key. Nothing is claimed
			// and nothing needs guarding; counted so the exemption is explicit.
			ownKeySites++
		default:
			t.Errorf("entry.Sender assigned from an unrecognised origin at %s: %s",
				fset.Position(assign.Pos()), origin)
		}
		return true
	})

	for _, pos := range unguardedRingMemberSites {
		t.Errorf("ring member attributed as sender without a ring-size-2 guard at %s", pos)
	}

	// Non-vacuity. Without these the test would pass on a file that had lost the
	// attribution logic entirely, or on a parse that matched nothing at all.
	if guardedRingMemberSites < 2 {
		t.Fatalf("expected both receiver payload paths to attribute under a ring-size-2 guard, found %d", guardedRingMemberSites)
	}
	if ownKeySites < 2 {
		t.Fatalf("expected both outgoing paths to attribute from the wallet's own key, found %d", ownKeySites)
	}
}

// TestSenderAttributionDoesNotReadTheClaimedIndex asserts the sender-chosen byte
// is never used to index the ring. The guard above would still pass if the byte
// were read and then clamped; this pins that it is not read at all.
func TestSenderAttributionDoesNotReadTheClaimedIndex(t *testing.T) {
	src, err := os.ReadFile(attributionSourceFile)
	if err != nil {
		t.Fatalf("reading %s: %v", attributionSourceFile, err)
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, attributionSourceFile, src, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", attributionSourceFile, err)
	}

	// Any index into Publickeylist must use a locally derived index, never one
	// read out of the payload. The index is resolved back to the statement that
	// produced it: checking the index expression alone would miss the obvious
	// regression, where `sender_idx := uint(payload[0])` is reinstated and the
	// ring is then indexed by the innocent-looking name.
	var offenders []string
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)

		idx, ok := n.(*ast.IndexExpr)
		if !ok {
			return true
		}
		if !strings.Contains(sourceOf(fset, src, idx.X), "Publickeylist") {
			return true
		}
		index := sourceOf(fset, src, idx.Index)
		origin := originOf(fset, src, stack, idx.Index)
		if strings.Contains(origin, "payload") || strings.Contains(origin, "RPCPayload") {
			offenders = append(offenders,
				fset.Position(idx.Pos()).String()+": "+index+" = "+origin)
		}
		return true
	})

	for _, o := range offenders {
		t.Errorf("ring indexed by a sender-supplied payload byte at %s", o)
	}
}
