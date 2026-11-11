package bootstrap

// Contract 表示内置应用接入契约，包含授权模式、SDK 最低版本和更新渠道。
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

// FirstPartyContracts 返回五个内置应用的契约副本，调用者可独立修改。
func FirstPartyContracts() []Contract {
	result := make([]Contract, len(firstPartyContracts))
	for index, contract := range firstPartyContracts {
		result[index] = contract
		result[index].AuthorizationModes = append([]string(nil), contract.AuthorizationModes...)
		result[index].UpdateChannels = append([]string(nil), contract.UpdateChannels...)
	}
	return result
}

// FirstPartyContract 按应用标识查询契约并返回副本。
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
