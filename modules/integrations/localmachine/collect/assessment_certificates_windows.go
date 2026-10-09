//go:build windows

package collect

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	assessmentCertProperty   = windows.NewLazySystemDLL("crypt32.dll").NewProc("CertGetCertificateContextProperty")
	assessmentProvParam      = windows.NewLazySystemDLL("advapi32.dll").NewProc("CryptGetProvParam")
	assessmentNCrypt         = windows.NewLazySystemDLL("ncrypt.dll")
	assessmentNCryptProperty = assessmentNCrypt.NewProc("NCryptGetProperty")
	assessmentNCryptFree     = assessmentNCrypt.NewProc("NCryptFreeObject")
)

// Native CRYPT_KEY_PROV_INFO layout; pointers reference its backing buffer.
type assessmentKeyProvider struct {
	Container      *uint16
	Provider       *uint16
	Type           uint32
	Flags          uint32
	ParameterCount uint32
	Parameters     unsafe.Pointer
	KeySpec        uint32
}

func collectMachineCertificates(c *assessmentCapture) error {
	name, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return err
	}
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM_W, 0, 0, windows.CERT_SYSTEM_STORE_LOCAL_MACHINE|windows.CERT_STORE_OPEN_EXISTING_FLAG|windows.CERT_STORE_READONLY_FLAG, uintptr(unsafe.Pointer(name)))
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	var cert *windows.CertContext
	defer func() {
		if cert != nil {
			_ = windows.CertFreeCertificateContext(cert)
		}
	}()
	for count := 0; ; count++ {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		// Enumeration frees the previous context, including on end/error.
		cert, err = windows.CertEnumCertificatesInStore(store, cert)
		if err != nil {
			if errors.Is(err, syscall.Errno(0x80092004)) {
				return nil
			}
			return err
		}
		if cert == nil {
			return nil
		}
		if count >= 10000 || cert.Length > 1<<20 {
			return errAssessmentLimit
		}
		public, err := x509.ParseCertificate(unsafe.Slice(cert.EncodedCert, cert.Length))
		if err != nil {
			c.failure(nativeCollectionResult(err))
			continue
		}
		thumbprint := sha1.Sum(public.Raw) // Certificate identifier, not a signature.
		oids := []string{}
		for _, extension := range public.Extensions {
			if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) {
				var usage []asn1.ObjectIdentifier
				if _, err := asn1.Unmarshal(extension.Value, &usage); err != nil {
					c.failure(nativeCollectionResult(err))
					continue
				}
				for _, oid := range usage {
					oids = append(oids, oid.String())
				}
			}
		}
		r := map[string]any{"Thumbprint": strings.ToUpper(hex.EncodeToString(thumbprint[:])), "NotBefore": public.NotBefore, "NotAfter": public.NotAfter, "EnhancedKeyUsage": oids}
		present, keyPath, err := certificateKeyPath(cert)
		if present != nil {
			r["HasPrivateKey"] = *present
		}
		r["KeyPath"] = keyPath
		result := nativeCollectionResult(err)
		r["KeyMetadataStatus"], r["KeyMetadataResult"] = result.Status, result
		// Unknown provider metadata is not an assertion about key safety.
		if err != nil {
			c.failure(result)
		}
		if err := c.add(r); err != nil {
			return err
		}
	}
}

func certificateKeyPath(cert *windows.CertContext) (*bool, string, error) {
	if err := assessmentCertProperty.Find(); err != nil {
		return nil, "", errors.ErrUnsupported
	}
	var size uint32
	ok, _, err := assessmentCertProperty.Call(uintptr(unsafe.Pointer(cert)), 2, 0, uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		if errors.Is(err, syscall.Errno(0x80092004)) {
			present := false
			return &present, "", nil
		}
		return nil, "", err
	}
	present := true
	if size < uint32(unsafe.Sizeof(assessmentKeyProvider{})) || size > 1<<20 {
		return &present, "", errAssessmentLimit
	}
	buffer := make([]byte, size)
	ok, _, err = assessmentCertProperty.Call(uintptr(unsafe.Pointer(cert)), 2, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		return &present, "", err
	}
	provider := (*assessmentKeyProvider)(unsafe.Pointer(&buffer[0]))
	providerName := windows.UTF16PtrToString(provider.Provider)
	providerType, flags := provider.Type, provider.Flags
	runtime.KeepAlive(buffer)
	// Only known software machine-key providers have predictable local files.
	// Do not activate hardware providers, prompt, heal associations, or export keys.
	if flags&0x20 == 0 {
		return &present, "", errors.ErrUnsupported
	}
	cng := providerType == 0 && providerName == "Microsoft Software Key Storage Provider"
	csp := false
	switch providerName {
	case "Microsoft Base Cryptographic Provider v1.0", "Microsoft Enhanced Cryptographic Provider v1.0", "Microsoft Strong Cryptographic Provider", "Microsoft RSA SChannel Cryptographic Provider", "Microsoft Enhanced RSA and AES Cryptographic Provider":
		csp = providerType == 1 || providerType == 12 || providerType == 24
	}
	if !cng && !csp {
		return &present, "", errors.ErrUnsupported
	}
	if cng {
		if assessmentNCryptProperty.Find() != nil || assessmentNCryptFree.Find() != nil {
			return &present, "", errors.ErrUnsupported
		}
	} else if assessmentProvParam.Find() != nil {
		return &present, "", errors.ErrUnsupported
	}
	var key windows.Handle
	var keySpec uint32
	var release bool
	// SILENT | NO_HEALING | ALLOW_NCRYPT_KEY. Metadata access only.
	err = windows.CryptAcquireCertificatePrivateKey(cert, 0x40|0x8|0x10000, nil, &key, &keySpec, &release)
	if err != nil {
		return &present, "", err
	}
	defer func() {
		if release {
			if keySpec == 0xffffffff {
				assessmentNCryptFree.Call(uintptr(key))
			} else {
				_ = windows.CryptReleaseContext(key, 0)
			}
		}
	}()
	var unique, relative string
	if keySpec == 0xffffffff {
		property, _ := windows.UTF16PtrFromString("Unique Name")
		name := make([]uint16, 4096)
		status, _, _ := assessmentNCryptProperty.Call(uintptr(key), uintptr(unsafe.Pointer(property)), uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)*2), uintptr(unsafe.Pointer(&size)), 0)
		if status != 0 {
			return &present, "", syscall.Errno(status)
		}
		unique, relative = windows.UTF16ToString(name), `Microsoft\Crypto\Keys`
	} else {
		name := make([]byte, 4096)
		size = uint32(len(name))
		ok, _, err := assessmentProvParam.Call(uintptr(key), 36, uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&size)), 0)
		if ok == 0 {
			return &present, "", err
		}
		unique, relative = strings.TrimRight(string(name[:min(size, uint32(len(name)))]), "\x00"), `Microsoft\Crypto\RSA\MachineKeys`
	}
	if unique == "" || unique == "." || unique == ".." || strings.ContainsAny(unique, `\/:`) {
		return &present, "", errors.ErrUnsupported
	}
	base := os.Getenv("ProgramData")
	if !filepath.IsAbs(base) || strings.HasPrefix(base, `\\`) {
		return &present, "", errors.ErrUnsupported
	}
	return &present, filepath.Join(base, relative, unique), nil
}
