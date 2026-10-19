package threshold

import "testing"

// Drive serialized message delivery between independently allocated party
// states, with one bad private evaluation. The complaint and public apology
// must repair the recipient's state and yield a common encryption key.
func TestDKGComplaintAndApology(t *testing.T) {
	parties := make([]*DKGParty, 3)
	var commitments, evaluations []DKGMessage
	for i := range parties {
		var err error
		parties[i], err = NewDKGParty(77, 3, 2, i)
		if err != nil {
			t.Fatal(err)
		}
		commit, private, err := parties[i].StartDealing()
		if err != nil {
			t.Fatal(err)
		}
		commitments = append(commitments, commit)
		evaluations = append(evaluations, private...)
	}
	broadcast := func(messages []DKGMessage) {
		t.Helper()
		for _, msg := range messages {
			for _, party := range parties {
				if err := party.Handle(clone(t, msg)); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	broadcast(commitments)
	for _, msg := range evaluations {
		if msg.Sender == 2 && msg.Receiver == 0 {
			msg.Data = []byte{42}
		}
		if err := parties[msg.Receiver].Handle(clone(t, msg)); err != nil {
			t.Fatal(err)
		}
	}
	var accusations, apologies []DKGMessage
	for _, party := range parties {
		msgs, err := party.StartAccusing()
		if err != nil {
			t.Fatal(err)
		}
		accusations = append(accusations, msgs...)
	}
	if len(accusations) != 1 || accusations[0].Sender != 0 || accusations[0].Receiver != 2 {
		t.Fatalf("expected one complaint against bad dealer, got %+v", accusations)
	}
	broadcast(accusations)
	for _, party := range parties {
		msgs, err := party.StartApologizing()
		if err != nil {
			t.Fatal(err)
		}
		apologies = append(apologies, msgs...)
	}
	if len(apologies) != 1 {
		t.Fatalf("expected one apology, got %d", len(apologies))
	}
	broadcast(apologies)
	var config PublicConfig
	secrets := make([]SecretShare, len(parties))
	for i, party := range parties {
		public, secret, err := party.Finalize()
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && public.ID != config.ID {
			t.Fatal("parties disagree after apology")
		}
		config, secrets[i] = public, secret
		if _, _, err := party.Finalize(); err == nil {
			t.Fatal("finalized DKG state remained reusable")
		}
	}
	ct, err := Encrypt(config, []byte("after-apology"), []byte("restored"))
	if err != nil {
		t.Fatal(err)
	}
	var shares []DecryptionShare
	for _, secret := range secrets[:2] {
		share, err := CreateDecryptionShare(config, secret, ct)
		if err != nil {
			t.Fatal(err)
		}
		shares = append(shares, share)
	}
	plain, err := Decrypt(config, ct, shares)
	if err != nil || string(plain) != "restored" {
		t.Fatalf("repaired DKG failed decryption: %q %v", plain, err)
	}
}

func TestDKGRejectsMalformedMessagesAndTransitions(t *testing.T) {
	party, err := NewDKGParty(99, 3, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := party.StartAccusing(); err == nil {
		t.Fatal("out of order phase transition accepted")
	}
	commit, _, err := party.StartDealing()
	if err != nil {
		t.Fatal(err)
	}
	if err := party.Handle(commit); err != nil {
		t.Fatal(err)
	}
	if err := party.Handle(commit); err == nil {
		t.Fatal("duplicate commitment accepted")
	}
	for _, sender := range []int{-1, 3, 1 << 30} {
		bad := clone(t, commit)
		bad.Sender = sender
		if err := party.Handle(bad); err == nil {
			t.Fatalf("out of range sender %d accepted", sender)
		}
	}
	bad := clone(t, commit)
	bad.Sender, bad.Eon = 1, 100
	if err := party.Handle(bad); err == nil {
		t.Fatal("cross-ceremony message accepted")
	}
	bad.Eon, bad.Data = 99, nil
	if err := party.Handle(bad); err == nil {
		t.Fatal("empty commitments accepted")
	}
	accusations, err := party.StartAccusing()
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range accusations {
		if err := party.Handle(msg); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := party.StartApologizing(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := party.Finalize(); err == nil {
		t.Fatal("one participant incorrectly finalized a threshold-two DKG")
	}
}
