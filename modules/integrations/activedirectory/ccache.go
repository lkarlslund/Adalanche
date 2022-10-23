package activedirectory

import (
	"fmt"
	"log"
	"os"
	"strings"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
)

const (
	libdefault = `[libdefaults]
default_realm = %s
dns_lookup_realm = false
dns_lookup_kdc = false
ticket_lifetime = 24h
renew_lifetime = 5
forwardable = yes
proxiable = true
default_tkt_enctypes = rc4-hmac
default_tgs_enctypes = rc4-hmac
noaddresses = true
udp_preference_limit=1
[realms]
%s = {
kdc = %s:88
default_domain = %s
}`
)


func CcacheAuth(domain string, dc string) *client.Client {

	var cl *client.Client
	var err error

	domain = strings.ToUpper(domain)
	c, _ := config.NewFromString(fmt.Sprintf(libdefault, domain, domain, dc, domain))

	ccache, _ := credentials.LoadCCache(os.Getenv("KRB5CCNAME"))
	cl, err = client.NewFromCCache(ccache, c)
	if err != nil {
			log.Fatal(err)
	}

	return cl

}
