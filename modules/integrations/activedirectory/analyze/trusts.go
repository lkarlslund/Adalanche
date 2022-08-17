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
	Source, Target string
}

type TrustInfo struct {
	Direction  TrustDirection
	Attributes int
}

var TrustMap gsync.MapOf[TrustPair, TrustInfo]
