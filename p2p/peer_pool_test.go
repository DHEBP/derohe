package p2p

import (
	"math"
	"testing"
)

func TestPeerScore(t *testing.T) {
	now := uint64(1_000_000_000) // fixed epoch for deterministic tests

	tests := []struct {
		name         string
		peer         *Peer
		now          uint64
		expected     float64
		tolerance    float64
	}{
		{
			name:     "zero peer — all fields zero",
			peer:     &Peer{},
			now:      now,
			expected: 0.0,
			tolerance: 0.01,
		},
		{
			name: "5 successes, no latency data",
			peer: &Peer{SuccessCount: 5},
			now:  now,
			expected: 50.0,
			tolerance: 0.01,
		},
		{
			name: "3 failures only",
			peer: &Peer{FailCount: 3},
			now:  now,
			expected: -150.0,
			tolerance: 0.01,
		},
		{
			name: "5 successes, 10ms latency",
			peer: &Peer{
				SuccessCount: 5,
				LastLatency:  10_000_000,  // 10ms in ns
				LastMeasured: now - 60,    // 1 min ago
			},
			now:      now,
			expected: 50.0 + 10000.0/11.0, // ≈ 959.09
			tolerance: 0.01,
		},
		{
			name: "5 successes, 100ms latency",
			peer: &Peer{
				SuccessCount: 5,
				LastLatency:  100_000_000, // 100ms in ns
				LastMeasured: now - 60,
			},
			now:      now,
			expected: 50.0 + 10000.0/101.0, // ≈ 149.01
			tolerance: 0.01,
		},
		{
			name: "5 successes, 200ms latency",
			peer: &Peer{
				SuccessCount: 5,
				LastLatency:  200_000_000, // 200ms in ns
				LastMeasured: now - 60,
			},
			now:      now,
			expected: 50.0 + 10000.0/201.0, // ≈ 99.75
			tolerance: 0.01,
		},
		{
			name: "5 successes, TTL expired (25h old)",
			peer: &Peer{
				SuccessCount: 5,
				LastLatency:  10_000_000,
				LastMeasured: now - 25*3600, // 25 hours ago
			},
			now:      now,
			expected: 50.0, // no latency bonus (age >= 24h)
			tolerance: 0.01,
		},
		{
			name: "5 successes, TTL boundary (exactly 24h)",
			peer: &Peer{
				SuccessCount: 5,
				LastLatency:  10_000_000,
				LastMeasured: now - 24*3600, // exactly 24 hours
			},
			now:      now,
			expected: 50.0, // no bonus: age < 86400 is false
			tolerance: 0.01,
		},
		{
			name: "5 successes, TTL just barely valid (24h - 1s)",
			peer: &Peer{
				SuccessCount: 5,
				LastLatency:  10_000_000,
				LastMeasured: now - (24*3600 - 1), // 23h59m59s ago
			},
			now:      now,
			expected: 50.0 + 10000.0/11.0, // ≈ 959.09
			tolerance: 0.01,
		},
		{
			name: "5 successes, 1ms latency (very fast)",
			peer: &Peer{
				SuccessCount: 5,
				LastLatency:  1_000_000, // 1ms in ns
				LastMeasured: now - 60,
			},
			now:      now,
			expected: 50.0 + 5000.0, // 10000/(1+1) = 5000, total = 5050.0
			tolerance: 0.01,
		},
		{
			name: "1 success, 5 failures, 10ms latency (negative base)",
			peer: &Peer{
				SuccessCount: 1,
				FailCount:    5,
				LastLatency:  10_000_000,
				LastMeasured: now - 60,
			},
			now:      now,
			expected: -240.0 + 10000.0/11.0, // -240 + 909.09 = 669.09
			tolerance: 0.01,
		},
		{
			name: "zero latency guard (LastLatency=0, LastMeasured>0)",
			peer: &Peer{
				SuccessCount: 5,
				LastLatency:  0,
				LastMeasured: now - 60,
			},
			now:      now,
			expected: 50.0, // no bonus: LastLatency == 0 skips block
			tolerance: 0.01,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := peerScore(tt.peer, tt.now)
			diff := math.Abs(got - tt.expected)
			if diff > tt.tolerance {
				t.Errorf("peerScore() = %.10f, want ≈ %.2f (diff = %.10f)", got, tt.expected, diff)
			}
		})
	}
}

func TestPeerScoreRelativeOrdering(t *testing.T) {
	now := uint64(1_000_000_000)

	fastPeer := &Peer{
		SuccessCount: 5,
		LastLatency:  10_000_000,  // 10ms
		LastMeasured: now - 60,
	}
	slowPeer := &Peer{
		SuccessCount: 5,
		LastLatency:  100_000_000, // 100ms
		LastMeasured: now - 60,
	}
	verySlowPeer := &Peer{
		SuccessCount: 5,
		LastLatency:  200_000_000, // 200ms
		LastMeasured: now - 60,
	}
	noLatencyPeer := &Peer{
		SuccessCount: 5,
	}
	greyPeer := &Peer{} // greylist: no success, no latency

	scores := []struct {
		name  string
		score float64
	}{
		{"fastPeer (10ms)", peerScore(fastPeer, now)},
		{"slowPeer (100ms)", peerScore(slowPeer, now)},
		{"verySlowPeer (200ms)", peerScore(verySlowPeer, now)},
		{"noLatencyPeer", peerScore(noLatencyPeer, now)},
		{"greyPeer", peerScore(greyPeer, now)},
	}

	for i := 0; i < len(scores)-1; i++ {
		if scores[i].score < scores[i+1].score {
			t.Errorf(
				"ordering violation: %s (%.2f) < %s (%.2f) — expected descending",
				scores[i].name, scores[i].score,
				scores[i+1].name, scores[i+1].score,
			)
		}
	}

	// also verify absolute values are sensible
	if fastPeerScore := peerScore(fastPeer, now); fastPeerScore < 900 {
		t.Errorf("fast peer (10ms) should score > 900, got %.2f", fastPeerScore)
	}
	if greyPeerScore := peerScore(greyPeer, now); greyPeerScore != 0.0 {
		t.Errorf("grey peer should score 0.0, got %.2f", greyPeerScore)
	}
}
