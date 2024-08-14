package collect

import (
	"fmt"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/lkarlslund/adalanche/modules/ui"
)

type GSSAPIState struct {
	cfg    *config.Config
	client *client.Client

	token  spnego.KRB5Token
	ekey   types.EncryptionKey
	Subkey types.EncryptionKey
	asrep  bool
}

func (state *GSSAPIState) DeleteSecContext() error {
	return nil
}

func (state *GSSAPIState) InitSecContext(target string, _ []byte) (outputToken []byte, needContinue bool, err error) {
	tkt, key, err := state.client.GetServiceTicket(target)
	if err != nil {
		ui.Fatal().Msgf("Problem getting service ticket: %v", err)
	}

	token, err := spnego.NewKRB5TokenAPREQ(state.client, tkt, key, []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual}, []int{flags.APOptionMutualRequired})
	if err != nil {
		ui.Fatal().Msgf("Problem getting AP req: %v", err)
	}

	state.ekey = key
	state.token = token

	outputToken, err = token.Marshal()
	if err != nil {
		ui.Fatal().Msgf("Problem getting token: %v", err)
	}
	needContinue = false
	return
}

func (state *GSSAPIState) NegotiateSaslAuth(input []byte, authzid string) ([]byte, error) {
	if !state.asrep {
		err := state.token.Unmarshal(input)
		if err != nil {
			return nil, err
		}

		if state.token.IsAPRep() {
			state.asrep = true

			encpart, err := crypto.DecryptEncPart(state.token.APRep.EncPart, state.ekey, keyusage.AP_REP_ENCPART)
			if err != nil {
				return nil, err
			}

			part := &messages.EncAPRepPart{}
			err = part.Unmarshal(encpart)
			if err != nil {
				return nil, err
			}

			state.Subkey = part.Subkey
		}

		if state.token.IsKRBError() {
			return nil, state.token.KRBError
		}

		return make([]byte, 0), nil
	}

	token := &gssapi.WrapToken{}
	err := token.Unmarshal(input, true)
	if err != nil {
		return nil, err
	}

	if (token.Flags & 0b1) == 0 {
		return nil, fmt.Errorf("Got a Wrapped token that's not from the server")
	}

	key := state.ekey
	if (token.Flags & 0b100) != 0 {
		key = state.Subkey
	}

	if (token.Flags & 0b10) != 0 {
		_, err = token.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL)
		if err != nil {
			return nil, err
		}
	}

	pl := token.Payload
	if len(pl) != 4 {
		return nil, fmt.Errorf("Server send bad final token for SASL GSSAPI Handshake")
	}

	// We never want a security layer
	b := [4]byte{0, 0, 0, 0}
	payload := append(b[:], []byte(authzid)...)

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}

	token = &gssapi.WrapToken{
		Flags:     0b100,
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: 1,
		Payload:   payload,
	}

	if err := token.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}

	return token.Marshal()
}
