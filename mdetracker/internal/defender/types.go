package defender

import (
	"encoding/json"
	"time"
)

// Machine is the subset of the Defender for Endpoint machine entity we use.
// https://learn.microsoft.com/defender-endpoint/api/machine
type Machine struct {
	ID                    string      `json:"id"`
	ComputerDNSName       string      `json:"computerDnsName"`
	FirstSeen             *time.Time  `json:"firstSeen"`
	LastSeen              *time.Time  `json:"lastSeen"`
	OSPlatform            string      `json:"osPlatform"`
	OSVersion             string      `json:"version"`
	OSProcessor           string      `json:"osProcessor"`
	LastIPAddress         string      `json:"lastIpAddress"`
	LastExternalIPAddress string      `json:"lastExternalIpAddress"`
	HealthStatus          string      `json:"healthStatus"`
	OnboardingStatus      string      `json:"onboardingStatus"`
	DefenderAVStatus      string      `json:"defenderAvStatus"`
	RiskScore             string      `json:"riskScore"`
	ExposureLevel         string      `json:"exposureLevel"`
	DeviceValue           string      `json:"deviceValue"`
	RBACGroupName         string      `json:"rbacGroupName"`
	IsAADJoined           bool        `json:"isAadJoined"`
	AADDeviceID           string      `json:"aadDeviceId"`
	ManagedBy             string      `json:"managedBy"`
	MachineTags           []string    `json:"machineTags"`
	VMMetadata            *VMMetadata `json:"vmMetadata"`

	// Raw is the machine exactly as the API returned it (every field), for debug dumps.
	Raw json.RawMessage `json:"-"`
}

type VMMetadata struct {
	VMID           string `json:"vmId"`
	CloudProvider  string `json:"cloudProvider"`
	ResourceID     string `json:"resourceId"`
	SubscriptionID string `json:"subscriptionId"`
}

// IsAzureVM reports whether Defender has Azure VM metadata for the device.
func (m Machine) IsAzureVM() bool {
	return m.VMMetadata != nil && (m.VMMetadata.ResourceID != "" || m.VMMetadata.VMID != "")
}

type machinesPage struct {
	Value    []json.RawMessage `json:"value"`
	NextLink string            `json:"@odata.nextLink"`
}
