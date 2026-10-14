package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
)

// IMDSAPIVersion is the Instance Metadata Service API version (PLAN §6.1).
const IMDSAPIVersion = "2021-02-01"

// InstanceMetadata is the subset of IMDS instance metadata labfw uses.
type InstanceMetadata struct {
	Location          string
	SubscriptionID    string
	ResourceGroupName string
	Name              string
	Interfaces        []NetworkInterface
}

// NetworkInterface lists one NIC's addresses (primary IP first, as IMDS
// returns them).
type NetworkInterface struct {
	MACAddress string
	PrivateIPs []netip.Addr
	PublicIPs  []netip.Addr
}

// PrivateIPs returns all private IPv4 addresses of all interfaces.
func (m *InstanceMetadata) PrivateIPs() []netip.Addr {
	var out []netip.Addr
	for _, nic := range m.Interfaces {
		out = append(out, nic.PrivateIPs...)
	}
	return out
}

// PublicIPs returns all public IPv4 addresses of all interfaces.
func (m *InstanceMetadata) PublicIPs() []netip.Addr {
	var out []netip.Addr
	for _, nic := range m.Interfaces {
		out = append(out, nic.PublicIPs...)
	}
	return out
}

// GetInstanceMetadata queries IMDS (Options.IMDSBaseURL) without
// authentication or retries; the default client has a 2s timeout and never
// uses a proxy.
func (c *Client) GetInstanceMetadata(ctx context.Context) (*InstanceMetadata, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultIMDSTimeout)
	defer cancel()
	u := c.imdsURL + "/metadata/instance?api-version=" + IMDSAPIVersion
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("imds: build request: %w", err)
	}
	req.Header.Set("Metadata", "true")
	resp, err := c.imdsHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("imds: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("imds: read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("imds: %w", parseARMError(resp.StatusCode, c.imdsURL+"/metadata/instance", b))
	}
	return parseInstanceMetadata(b)
}

func parseInstanceMetadata(b []byte) (*InstanceMetadata, error) {
	var doc struct {
		Compute struct {
			Location          string `json:"location"`
			SubscriptionID    string `json:"subscriptionId"`
			ResourceGroupName string `json:"resourceGroupName"`
			Name              string `json:"name"`
		} `json:"compute"`
		Network struct {
			Interface []struct {
				MACAddress string `json:"macAddress"`
				IPv4       struct {
					IPAddress []struct {
						PrivateIPAddress string `json:"privateIpAddress"`
						PublicIPAddress  string `json:"publicIpAddress"`
					} `json:"ipAddress"`
				} `json:"ipv4"`
			} `json:"interface"`
		} `json:"network"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("imds: decode: %w", err)
	}
	m := &InstanceMetadata{
		Location:          doc.Compute.Location,
		SubscriptionID:    doc.Compute.SubscriptionID,
		ResourceGroupName: doc.Compute.ResourceGroupName,
		Name:              doc.Compute.Name,
	}
	for _, nic := range doc.Network.Interface {
		n := NetworkInterface{MACAddress: nic.MACAddress}
		for _, a := range nic.IPv4.IPAddress {
			if a.PrivateIPAddress != "" {
				ip, err := netip.ParseAddr(a.PrivateIPAddress)
				if err != nil {
					return nil, fmt.Errorf("imds: private IP %q: %w", a.PrivateIPAddress, err)
				}
				n.PrivateIPs = append(n.PrivateIPs, ip)
			}
			if a.PublicIPAddress != "" {
				ip, err := netip.ParseAddr(a.PublicIPAddress)
				if err != nil {
					return nil, fmt.Errorf("imds: public IP %q: %w", a.PublicIPAddress, err)
				}
				n.PublicIPs = append(n.PublicIPs, ip)
			}
		}
		m.Interfaces = append(m.Interfaces, n)
	}
	return m, nil
}
