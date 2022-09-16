package analyze

import gsync "github.com/SaveTheRbtz/generic-sync-map-go"

type TrustDirection byte

const (
	Disabled TrustDirection = iota
	Incoming
	Outgoing
	Bidirectional
)

type TrustPair struct {
	SourceNCName  string // Naming Context (dc=contoso,dc=com)
	SourceDNSRoot string // DNS root (contoso.com)
	SourceNetbios string // NETBIOS translation for above (CONTOSO)
	SourceSID     string // Domain SID (s-1-5-21-1111111111-1111111111-111111111-1111111)
	TargetDNSRoot string // Target DNS root (factory.contoso.com)
}

type TrustInfo struct {
	Direction  TrustDirection
	Attributes int
}

var TrustMap gsync.MapOf[TrustPair, TrustInfo]
