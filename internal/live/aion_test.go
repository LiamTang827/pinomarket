package live

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func newAionTestFixture(t *testing.T) (liveTestFixture, []ed25519.PrivateKey) {
	t.Helper()
	f := newLiveTestFixture(t)
	f.manifest.Policy.Ingress = IngressSoftware
	f.manifest.Policy.Ordering = OrderingAion
	f.manifest.Policy.Aion = &AionPolicy{ClockSkewMS: 5, DelayVariationMS: 10, MaxDelayMS: 100}
	keys := make([]ed25519.PrivateKey, len(f.manifest.Peers))
	for i := range f.manifest.Peers {
		public, private, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		f.manifest.Peers[i].IngressKey = public
		keys[i] = private
	}
	f.manifest.Context = f.manifest.ContextID()
	if err := f.manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	return f, keys
}

func TestAionProofBindsPacketAndRejectsInvalidVotes(t *testing.T) {
	f, keys := newAionTestFixture(t)
	packet := f.packet(t, 1, "alice", 1)
	m := f.manifest
	ms := int64(time.Millisecond)
	claim := TimeClaim{Context: m.Context, Round: 1, Origin: m.Peers[0].ID, PacketID: packet.ID(), Time: 1000 * ms}
	claim.Signature = Sign(keys[0], claim.body())
	proof := TimeProof{Claim: claim}
	for i := 0; i < m.Policy.Quorum; i++ {
		vote := TimeVote{Verifier: m.Peers[i].ID, Received: claim.Time + 20*ms, Delay: 18 * ms}
		vote.Signature = Sign(keys[i], vote.body(claim))
		proof.Votes = append(proof.Votes, vote)
	}
	packet.TimeProof = &proof
	if err := packet.ValidateAdmission(m); err != nil {
		t.Fatalf("valid timing proof rejected: %v", err)
	}
	otherPacket := f.packet(t, 2, "alice", 2)
	otherPacket.TimeProof = &proof
	if err := otherPacket.ValidateAdmission(m); err == nil {
		t.Fatal("proof accepted for another packet/round")
	}

	original := proof.Votes[1]
	proof.Votes[1] = proof.Votes[0]
	if err := proof.Validate(m, packet); err == nil {
		t.Fatal("duplicate verifier counted toward quorum")
	}
	proof.Votes[1] = original
	proof.Votes[1].Received = claim.Time + original.Delay + 15*ms + 1
	proof.Votes[1].Signature = Sign(keys[1], proof.Votes[1].body(claim))
	if err := proof.Validate(m, packet); err == nil {
		t.Fatal("signed vote outside the timing tolerance accepted")
	}
	proof.Votes[1] = original
	proof.Claim.Time--
	if err := proof.Validate(m, packet); err == nil {
		t.Fatal("unsigned change to the claimed time accepted")
	}
}

func TestAionMeasurementPinSurvivesRestart(t *testing.T) {
	f, keys := newAionTestFixture(t)
	m := f.manifest
	verifier, origin := m.Peers[0].ID, m.Peers[1].ID
	path := filepath.Join(t.TempDir(), "aion-delay.json")
	runtime := newAionRuntime(keys[0], path)
	first := aionMeasurement{ReplyTime: 200, Received: 250}
	second := aionMeasurement{ReplyTime: 400, Received: 490}
	if err := runtime.pin(m, verifier, origin, 1, first); err != nil {
		t.Fatal(err)
	}
	restarted := newAionRuntime(keys[0], path)
	if err := restarted.pin(m, verifier, origin, 1, second); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := restarted.measurement(m, verifier, origin, 1); err != nil || !ok || got != first {
		t.Fatalf("pinned delay was replaced after restart: got %v, found %v, error %v", got, ok, err)
	}
	if err := restarted.pin(m, verifier, origin, 2, second); err != nil {
		t.Fatal(err)
	}
	if err := restarted.pin(m, verifier, origin, 1, first); err == nil {
		t.Fatal("old round overwrote current calibration")
	}
}

type aionTestTransport func(*http.Request) (*http.Response, error)

func (f aionTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAionCalibrationRejectsReplayedChallengeResponse(t *testing.T) {
	f, keys := newAionTestFixture(t)
	m := f.manifest
	origin, verifier := m.Peers[0].ID, m.Peers[1].ID
	runtime := newAionRuntime(keys[1], filepath.Join(t.TempDir(), "aion-delay.json"))
	node := &liveNode{
		cfg: NodeConfig{Manifest: m}, peer: m.Peers[1], aion: runtime,
		machine: &Machine{state: &State{Height: 1, Round: &Round{Number: 1, CloseHeight: 4}}},
	}
	old := aionChallenge{Context: m.Context, Round: 1, Origin: origin, Verifier: verifier, Nonce: [32]byte{1}}
	old.Signature = Sign(keys[1], old.body())
	runtime.client.Transport = aionTestTransport(func(r *http.Request) (*http.Response, error) {
		reply := aionReply{Challenge: Hash(old), Time: time.Now().UnixNano()}
		reply.Signature = Sign(keys[0], reply.body())
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(JSON(reply)))}, nil
	})
	request := aionCalibrationRequest{Context: m.Context, Round: 1, Origin: origin}
	request.Signature = Sign(keys[0], request.body())
	response := httptest.NewRecorder()
	node.calibrateTime(response, httptest.NewRequest(http.MethodPost, "/aion/calibrate", bytes.NewReader(JSON(request))))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected stale response rejection, got %d: %s", response.Code, response.Body.String())
	}
	if _, ok, err := runtime.measurement(m, verifier, origin, 1); err != nil || ok {
		t.Fatalf("old challenge response created a pin: present %v, error %v", ok, err)
	}
}
