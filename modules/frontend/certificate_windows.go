//go:build !32bit
// +build !32bit

package frontend

import (
	"crypto/tls"

	"github.com/google/certtostore"
	"github.com/lkarlslund/adalanche/modules/ui"
)

var UseWindowsCert = Command.Flags().Bool("usewindowscert", true, "Try to autoload a certificate from the Windows Certificate store and use that for https")

func init() {
	AddOption(func(ws *WebService) error {
		if !*UseWindowsCert {
			return nil
		}

		if ws.srv.TLSConfig != nil {
			ui.Info().Msg("Skipping autoloading Windows certificate, TLS already configured")
			return nil
		}

		// Open the local cert store. Provider generally shouldn't matter, so use Software which is ubiquitous. See comments in getHostKey.
		store, err := certtostore.OpenWinCertStore(certtostore.ProviderMSSoftware, "", []string{"localhost"}, nil, false)

		if err != nil {
			ui.Warn().Msgf("Opening Windows certificate store failed: %v, trying platform mode", err)
			store, err = certtostore.OpenWinCertStore(certtostore.ProviderMSPlatform, "", []string{"localhost"}, nil, false)
		}

		if err != nil {
			ui.Warn().Msgf("Opening Windows certificate store failed: %v, continuing without it", err)
			return nil
		}

		crt, context, err := store.CertWithContext()
		if err != nil {
			ui.Warn().Msgf("Auto-loading Windows certificate failed: %v, continuing without it", err)
			return nil
		}

		if crt == nil {
			ui.Warn().Msgf("No usable certificate found in Windows certificate store")
			return nil
		}

		key, err := store.CertKey(context)
		if err != nil {
			ui.Warn().Msgf("Auto-loading Windows certificate private key failed: %v, continuing without it", err)
			return nil
		}

		if key == nil {
			ui.Warn().Msgf("No usable certificate private key found in Windows certificate store")
			return nil
		}

		ws.protocol = "https"
		ws.srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{tls.Certificate{
				Certificate: [][]byte{crt.Raw},
				PrivateKey:  key}},
		}

		return nil
	})
}
