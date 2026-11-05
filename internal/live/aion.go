package live

import (
	"errors"
	"time"
)

// AionPolicy configures the model's timing tolerances. These are assumptions,
// not bounds measured or established by the software backend.
type AionPolicy struct {
	ClockSkewMS      int64 `json:"clock_skew_ms"`
	DelayVariationMS int64 `json:"delay_variation_ms"`
	MaxDelayMS       int64 `json:"max_delay_ms"`
}

func (p AionPolicy) Validate() error {
	const limit = 60_000
	if p.ClockSkewMS < 0 || p.ClockSkewMS > limit ||
		p.DelayVariationMS < 0 || p.DelayVariationMS > limit ||
		p.MaxDelayMS < 1 || p.MaxDelayMS > limit {
		return errors.New("invalid Aion timing policy")
	}
	return nil
}

func (p AionPolicy) validDelay(delay int64) bool {
	return delay >= -p.ClockSkewMS*int64(time.Millisecond) &&
		delay <= p.MaxDelayMS*int64(time.Millisecond)
}

func (p AionPolicy) matches(claimed, received, delay int64) bool {
	if claimed <= 0 || received <= 0 || !p.validDelay(delay) {
		return false
	}
	// Compare the difference directly. Subtracting delay from an arbitrary
	// claimed timestamp first can overflow for malformed input.
	observedDelay := received - claimed
	tolerance := (p.ClockSkewMS + p.DelayVariationMS) * int64(time.Millisecond)
	return observedDelay >= delay-tolerance && observedDelay <= delay+tolerance
}

type TimeClaim struct {
	Context   string `json:"context"`
	Round     int    `json:"round"`
	Origin    string `json:"origin"`
	PacketID  string `json:"packet_id"`
	Time      int64  `json:"unix_nano"`
	Signature []byte `json:"signature,omitempty"`
}

func (c TimeClaim) body() any {
	c.Signature = nil
	return timingBody("claim", c)
}

func (c TimeClaim) validate(m Manifest, packet Packet) error {
	peer, ok := m.Peer(c.Origin)
	if !ok || c.Context != m.Context || c.Context != packet.Header.Context || c.Round < 1 ||
		c.Round != packet.Header.Round || c.PacketID != packet.ID() || c.Time <= 0 ||
		!Verify(peer.IngressKey, c.body(), c.Signature) {
		return errors.New("invalid Aion time claim")
	}
	return nil
}

type TimeVote struct {
	Verifier  string `json:"verifier"`
	Received  int64  `json:"received_unix_nano"`
	Delay     int64  `json:"delay_nano"`
	Signature []byte `json:"signature,omitempty"`
}

func (v TimeVote) body(c TimeClaim) any {
	v.Signature = nil
	return timingBody("vote", struct {
		Claim TimeClaim `json:"claim"`
		Vote  TimeVote  `json:"vote"`
	}{c, v})
}

func (v TimeVote) validate(m Manifest, c TimeClaim) error {
	peer, ok := m.Peer(v.Verifier)
	if !ok || m.Policy.Aion == nil || !m.Policy.Aion.matches(c.Time, v.Received, v.Delay) ||
		!Verify(peer.IngressKey, v.body(c), v.Signature) {
		return errors.New("invalid Aion time vote")
	}
	return nil
}

// TimeProof binds a broadcast request to a quorum of distinct time verifiers.
// The signatures attest to each verifier's locally pinned measurement.
type TimeProof struct {
	Claim TimeClaim  `json:"claim"`
	Votes []TimeVote `json:"votes"`
}

func (p *TimeProof) Timestamp() int64 { return p.Claim.Time }

func (p *TimeProof) Validate(m Manifest, packet Packet) error {
	if p == nil || m.Policy.Aion == nil || m.Policy.Quorum < 1 ||
		len(p.Votes) != m.Policy.Quorum {
		return errors.New("missing Aion time proof or incorrect quorum size")
	}
	if err := m.Policy.Aion.Validate(); err != nil {
		return err
	}
	if err := p.Claim.validate(m, packet); err != nil {
		return err
	}
	previous := ""
	for _, vote := range p.Votes {
		if vote.Verifier <= previous {
			return errors.New("Aion time votes must be ordered and have distinct verifiers")
		}
		if err := vote.validate(m, p.Claim); err != nil {
			return err
		}
		previous = vote.Verifier
	}
	return nil
}

func timingBody(kind string, value any) any {
	return struct {
		Domain string `json:"domain"`
		Value  any    `json:"value"`
	}{"pinocchio/aion/v1/" + kind, value}
}
