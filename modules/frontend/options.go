package frontend

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"

	"github.com/gin-contrib/pprof"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/util"
)

// WithCert is a webservice modifier that switches to HTTPS using a provided certificate
func WithCert(certfile, keyfile string) optionsetter {
	return func(ws *WebService) error {
		// create certificate from pem strings directly
		var cert tls.Certificate
		var err error
		if util.PathExists(certfile) && util.PathExists(keyfile) {
			cert, err = tls.LoadX509KeyPair(certfile, keyfile)
		} else {
			cert, err = tls.X509KeyPair([]byte(certfile), []byte(keyfile))
		}
		if err != nil {
			return err
		}
		ws.protocol = "https"
		ws.srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		ui.Info().Msgf("Certificate loaded and configured for DNS names %v", strings.Join(ws.srv.TLSConfig.Certificates[0].Leaf.DNSNames, ", "))
		return nil
	}
}

// WithLocalHTML adds live files to the webservice from a given path
func WithLocalHTML(path string) optionsetter {
	return func(ws *WebService) error {
		if !ws.localhtmlused {
			// Clear embedded html filesystem
			ws.UnionFS = UnionFS{}
			ws.localhtmlused = true
		}
		// Override embedded HTML if asked to
		stat, err := os.Stat(path)
		if err == nil && stat.IsDir() {
			// Use local files if they exist
			ui.Info().Msgf("Adding local HTML folder %v", path)
			ws.AddFS(os.DirFS(path))
			return nil
		}
		return fmt.Errorf("could not add local HTML folder %v, failure: %v", path, err)
	}
}

// WithProfiling is a webservice modifier that enables pprof profiling endpoints on the web service.
func WithProfiling() func(*WebService) {
	return func(ws *WebService) {
		// Profiling
		pprof.Register(ws.Router)
	}
}
