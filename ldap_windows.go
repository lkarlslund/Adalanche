package main

import (
	"errors"
)

func (ad *AD) gssapiConnect() error {
	/*
		cred, err := negotiate.AcquireCurrentUserCredentials()
		if err != nil {
			return err
		}
		defer cred.Release()

		secctx, token, err := negotiate.NewClientContext(cred, "ldap/"+ad.Server)
		if err != nil {
			return err
		}
		defer secctx.Release()
		spew.Dump(token)

		ad.conn.GSSAPIBind(ad.Server, "ldap", token)*/
	return errors.New("Not implemented")
}
