package engine

// Attributes that hold passwords, password hashes, keys or other secrets.
// They are named here, rather than by the integrations that read them,
// because attributes are shared by name: an attribute an import creates
// from whatever a directory holds is the same attribute, and flagged.
var secretAttributes = []string{
	// Account passwords and hashes
	"unicodePwd", "dBCSPwd", "dBSSPwd", "ntPwdHistory", "lmPwdHistory",
	"supplementalCredentials", "userPassword", "unixUserPassword",
	"plaintextPwd",
	// Managed and local administrator passwords
	"msDS-ManagedPassword", "ms-Mcs-AdmPwd", "msLAPS-Password",
	"msLAPS-EncryptedPassword", "msLAPS-EncryptedPasswordHistory",
	"msLAPS-EncryptedDSRMPassword", "msLAPS-EncryptedDSRMPasswordHistory",
	// BitLocker recovery and key material
	"msFVE-RecoveryPassword", "ms-FVE-RecoveryPassword", "msFVE-KeyPackage",
	// Credential roaming
	"msPKIAccountCredentials", "msPKIDPAPIMasterKeys",
	// Passwords found in group policy and elsewhere
	"exposedPassword", "cpassword",
	// Trust passwords
	"trustAuthIncoming", "trustAuthOutgoing", "initialAuthIncoming", "initialAuthOutgoing",
}

func init() {
	for _, name := range secretAttributes {
		NewAttribute(name).Flag(Secret)
	}
}
