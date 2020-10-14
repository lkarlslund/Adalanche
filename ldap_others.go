// +build !windows

package main

import (
	"errors"
)

func (ad *AD) gssapiConnect() error {
	/*
		cfgPath := os.Getenv("KRB5_CONFIG")
		if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
			cfgPath = "/etc/krb5.conf" // ToDo: Macs and Windows have different path, also some Unix may have /etc/krb5/krb5.conf
		}

		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}

		u, err := user.Current()
		if err != nil {
			return err
		}

		ccpath := "/tmp/krb5cc_" + u.Uid

		ccname := os.Getenv("KRB5CCNAME")
		if strings.HasPrefix(ccname, "FILE:") {
			ccpath = strings.SplitN(ccname, ":", 2)[1]
		}

		ccache, err := credentials.LoadCCache(ccpath)
		if err != nil {
			return err
		}

		cl, err := client.NewClientFromCCache(ccache)
		if err != nil {
			return err
		}

		cl.GoKrb5Conf.DisablePAFXFast = true
		cl.WithConfig(cfg)
	*/
	return errors.New("Not implemented for non-Windows")
}
