package bootstrap

import "testing"

func TestFirstPartyContractsAreStableAndDefensive(t *testing.T) {
	contracts := FirstPartyContracts()
	if len(contracts) != 5 {
		t.Fatalf("contract count = %d, want 5", len(contracts))
	}
	contracts[0].AuthorizationModes[0] = "tampered"
	contract, ok := FirstPartyContract("go-dcim")
	if !ok || contract.AuthorizationModes[0] == "tampered" {
		t.Fatal("contract slices are not defensive")
	}
	if _, ok := FirstPartyContract("unknown"); ok {
		t.Fatal("unknown app unexpectedly has a contract")
	}
}
