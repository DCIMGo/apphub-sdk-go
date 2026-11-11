package bootstrap

// Contract is the runtime portion of the first-party application contract.
// Release tooling can use it to reject an application configuration that
// drifts from the platform registry.
type Contract struct {
	AppID              string
	MinimumSDKVersion  string
	AuthorizationModes []string
	RecommendedMode    string
	UpdateChannels     []string
}

var firstPartyContracts = []Contract{
	{AppID: "go-dcim", MinimumSDKVersion: "0.1.0", AuthorizationModes: []string{"offline", "activate_once", "online_lease"}, RecommendedMode: "offline", UpdateChannels: []string{"stable", "emergency", "customer"}},
	{AppID: "go-monitor", MinimumSDKVersion: "0.1.0", AuthorizationModes: []string{"offline", "online_lease"}, RecommendedMode: "online_lease", UpdateChannels: []string{"stable", "beta", "emergency"}},
	{AppID: "go-north", MinimumSDKVersion: "0.1.0", AuthorizationModes: []string{"activate_once", "online_lease"}, RecommendedMode: "online_lease", UpdateChannels: []string{"stable", "beta", "emergency"}},
	{AppID: "go-push", MinimumSDKVersion: "0.1.0", AuthorizationModes: []string{"offline", "activate_once"}, RecommendedMode: "activate_once", UpdateChannels: []string{"stable", "emergency"}},
	{AppID: "go-sample", MinimumSDKVersion: "0.1.0", AuthorizationModes: []string{"offline", "activate_once", "online_lease"}, RecommendedMode: "offline", UpdateChannels: []string{"stable", "beta"}},
}

// FirstPartyContracts returns a defensive copy of the five initial contracts.
func FirstPartyContracts() []Contract {
	result := make([]Contract, len(firstPartyContracts))
	for index, contract := range firstPartyContracts {
		result[index] = contract
		result[index].AuthorizationModes = append([]string(nil), contract.AuthorizationModes...)
		result[index].UpdateChannels = append([]string(nil), contract.UpdateChannels...)
	}
	return result
}

// FirstPartyContract returns one contract by stable App ID.
func FirstPartyContract(appID string) (Contract, bool) {
	for _, contract := range firstPartyContracts {
		if contract.AppID == appID {
			contract.AuthorizationModes = append([]string(nil), contract.AuthorizationModes...)
			contract.UpdateChannels = append([]string(nil), contract.UpdateChannels...)
			return contract, true
		}
	}
	return Contract{}, false
}
