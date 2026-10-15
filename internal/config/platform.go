package config

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// Platforms (PLAN §8.8).
const (
	// PlatformAzure is an Azure VM: IMDS, Azure DNS (168.63.129.16) and the
	// wire server are available. The default.
	PlatformAzure = "azure"
	// PlatformGeneric is any other Linux host (Hyper-V, KVM, Proxmox,
	// VMware, bare metal): no IMDS calls, no Azure DNS, no wire server.
	PlatformGeneric = "generic"
)

// Authentication modes of azure.auth (PLAN §6.1, §8.8).
const (
	// AuthAuto is managed identity then Azure CLI on platform azure; on
	// platform generic it is the Azure Arc identity (when the Arc agent is
	// installed) then Azure CLI. No IMDS call is made on platform generic.
	AuthAuto = "auto"
	// AuthManagedIdentity is the VM's managed identity (IMDS; platform azure).
	AuthManagedIdentity = "managedIdentity"
	// AuthArc is the managed identity of an Azure Arc-enabled server.
	AuthArc = "arc"
	// AuthClientCertificate is a service principal with a certificate.
	AuthClientCertificate = "clientCertificate"
	// AuthClientSecret is a service principal with a secret read from a file.
	AuthClientSecret = "clientSecret"
	// AuthAzureCLI uses `az login` (developer machines).
	AuthAzureCLI = "azureCLI"
)

// DNATInterface is the dnatAddressMap value meaning "the first IPv4
// address of network.interface" (the uplink; PLAN §8.8).
const DNATInterface = "interface"

// DNATPrimary is the dnatAddressMap value meaning "the VM's primary private
// IP" (network.localIPs[0], else IMDS, else the interface; S22).
const DNATPrimary = "primary"

var (
	guidRE     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	locationRE = regexp.MustCompile(`^[a-z][a-z0-9]{1,39}$`)
)

// IsGeneric reports whether labfw runs outside Azure (platform generic).
func (c *Config) IsGeneric() bool { return c.Platform == PlatformGeneric }

// TwoArmed reports whether internal (LAN) interfaces are configured.
func (c *Config) TwoArmed() bool { return len(c.Network.InternalInterfaces) > 0 }

// validateDNATValue checks one network.dnatAddressMap value.
func (c *Config) validateDNATValue(v string) []string {
	switch {
	case strings.EqualFold(v, DNATPrimary):
		if c.IsGeneric() {
			return []string{fmt.Sprintf("network.dnatAddressMap value %q is not available on platform generic "+
				"(no IMDS); use an explicit IP or %q (first IPv4 address of network.interface)", v, DNATInterface)}
		}
		return nil
	case strings.EqualFold(v, DNATInterface):
		return nil
	}
	if a, err := netip.ParseAddr(v); err != nil || !a.Unmap().Is4() {
		return []string{fmt.Sprintf("network.dnatAddressMap value %q: not an IPv4 address, %s or %s", v, DNATPrimary, DNATInterface)}
	}
	return nil
}

func (c *Config) validatePlatform() []string {
	var errs []string
	switch c.Platform {
	case PlatformAzure, PlatformGeneric:
	default:
		errs = append(errs, fmt.Sprintf("platform must be %s or %s, got %q", PlatformAzure, PlatformGeneric, c.Platform))
	}
	// An empty uplink stays accepted for one-armed configs (as before).
	if (c.Network.Interface != "" || c.TwoArmed()) && !ifaceNameRE.MatchString(c.Network.Interface) {
		errs = append(errs, fmt.Sprintf("network.interface %q is not a valid interface name", c.Network.Interface))
	}
	seen := map[string]bool{c.Network.Interface: true}
	for _, ifc := range c.Network.InternalInterfaces {
		switch {
		case !ifaceNameRE.MatchString(ifc):
			errs = append(errs, fmt.Sprintf("network.internalInterfaces: %q is not a valid interface name", ifc))
		case ifc == c.Network.Interface:
			errs = append(errs, fmt.Sprintf("network.internalInterfaces: %q is the uplink (network.interface)", ifc))
		case seen[ifc]:
			errs = append(errs, fmt.Sprintf("network.internalInterfaces: %q listed twice", ifc))
		case c.VPN.Enabled && ifc == c.VPN.Interface:
			errs = append(errs, fmt.Sprintf("network.internalInterfaces: %q is the VPN interface", ifc))
		}
		seen[ifc] = true
	}
	if c.Azure.Location != "" && !locationRE.MatchString(c.Azure.Location) {
		errs = append(errs, fmt.Sprintf("azure.location %q: want an Azure region name such as westeurope", c.Azure.Location))
	}
	return errs
}

func (c *Config) validateAuth() []string {
	a := &c.Azure
	var errs []string
	if a.ClientSecret != "" {
		// Never echo the value.
		errs = append(errs, "azure.clientSecret: inline secrets are not accepted; put the secret in a file "+
			"readable only by the labfw user and set azure.clientSecretFile")
	}
	needSP := func(mode string) {
		if !guidRE.MatchString(a.TenantID) {
			errs = append(errs, "azure.tenantId (a GUID) is required with azure.auth "+mode)
		}
		if !guidRE.MatchString(a.ClientID) {
			errs = append(errs, "azure.clientId (the application's client ID, a GUID) is required with azure.auth "+mode)
		}
	}
	unused := func(mode string, fields map[string]string) {
		keys := make([]string, 0, len(fields))
		for k := range fields {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			if fields[k] != "" {
				errs = append(errs, fmt.Sprintf("azure.%s is not used with azure.auth %s", k, mode))
			}
		}
	}
	switch a.Auth {
	case AuthAuto, AuthManagedIdentity:
		if a.Auth == AuthManagedIdentity && c.IsGeneric() {
			errs = append(errs, "azure.auth managedIdentity needs platform azure (IMDS); use arc for an Azure Arc-enabled server "+
				"or clientCertificate for a service principal")
		}
		unused(a.Auth, map[string]string{"tenantId": a.TenantID, "certificateFile": a.CertificateFile,
			"certificatePasswordFile": a.CertificatePasswordFile, "clientSecretFile": a.ClientSecretFile})
	case AuthArc:
		// Arc-enabled servers have only a system-assigned identity.
		unused(a.Auth, map[string]string{"clientId": a.ClientID, "tenantId": a.TenantID, "certificateFile": a.CertificateFile,
			"certificatePasswordFile": a.CertificatePasswordFile, "clientSecretFile": a.ClientSecretFile})
	case AuthClientCertificate:
		needSP(a.Auth)
		if a.CertificateFile == "" {
			errs = append(errs, "azure.certificateFile is required with azure.auth clientCertificate")
		}
		unused(a.Auth, map[string]string{"clientSecretFile": a.ClientSecretFile})
	case AuthClientSecret:
		needSP(a.Auth)
		if a.ClientSecretFile == "" {
			errs = append(errs, "azure.clientSecretFile is required with azure.auth clientSecret")
		}
		unused(a.Auth, map[string]string{"certificateFile": a.CertificateFile, "certificatePasswordFile": a.CertificatePasswordFile})
	case AuthAzureCLI:
		unused(a.Auth, map[string]string{"clientId": a.ClientID, "tenantId": a.TenantID, "certificateFile": a.CertificateFile,
			"certificatePasswordFile": a.CertificatePasswordFile, "clientSecretFile": a.ClientSecretFile})
	default:
		errs = append(errs, fmt.Sprintf("azure.auth must be one of %s, %s, %s, %s, %s, %s; got %q", AuthAuto, AuthManagedIdentity,
			AuthArc, AuthClientCertificate, AuthClientSecret, AuthAzureCLI, a.Auth))
	}
	return errs
}

// Interfaces returns the uplink followed by the internal interfaces.
func (c *Config) Interfaces() []string {
	return append([]string{c.Network.Interface}, c.Network.InternalInterfaces...)
}

// EffectiveDNATAddressMap returns network.dnatAddressMap with every
// "interface" value replaced by uplink (the first IPv4 address of
// network.interface). Entries mapping to "interface" are dropped when uplink
// is invalid, so the rules they would map stay unmapped (skipped, S22).
func (c *Config) EffectiveDNATAddressMap(uplink netip.Addr) map[string]string {
	out := make(map[string]string, len(c.Network.DNATAddressMap))
	for k, v := range c.Network.DNATAddressMap {
		if strings.EqualFold(v, DNATInterface) {
			if !uplink.IsValid() {
				continue
			}
			v = uplink.Unmap().String()
		}
		out[k] = v
	}
	return out
}

// UsesDNATInterface reports whether any dnatAddressMap value is "interface".
func (c *Config) UsesDNATInterface() bool {
	for _, v := range c.Network.DNATAddressMap {
		if strings.EqualFold(v, DNATInterface) {
			return true
		}
	}
	return false
}

// DefaultDNATAddressMap is the dnatAddressMap used when the config has
// none: {"*": "primary"} on platform azure (S22), {"*": "interface"} on
// platform generic.
func DefaultDNATAddressMap(platform string) map[string]string {
	if platform == PlatformGeneric {
		return map[string]string{"*": DNATInterface}
	}
	return map[string]string{"*": DNATPrimary}
}
