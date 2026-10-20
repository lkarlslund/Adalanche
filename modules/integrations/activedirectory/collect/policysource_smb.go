package collect

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"time"

	smb2 "github.com/cloudsoda/go-smb2"
	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

const smbSecurityFlags = smb2.OwnerSecurityInformation | smb2.DACLSecurityInformation

// smbPolicyClient is one authenticated SMB session with a mounted share. It lets
// GPO files be collected over the wire on non-Windows hosts, where the
// \\domain\sysvol path from gPCFileSysPath cannot be opened directly.
type smbPolicyClient struct {
	conn    net.Conn
	session *smb2.Session
	share   *smb2.Share
}

// smbInitiator returns a factory for SMB authenticators using the same
// credentials as the LDAP bind, or false if this bind has nothing SMB can reuse.
// Initiators keep per-session state, so every SMB session needs its own.
func (ad *AD) smbInitiator() (func() smb2.Initiator, bool) {
	if ad.krb5client != nil {
		krb5client, spn := ad.krb5client, "cifs/"+ad.server
		return func() smb2.Initiator {
			return &smb2.Krb5Initiator{Client: krb5client, TargetSPN: spn}
		}, true
	}
	if (ad.AuthMode == NTLM || ad.AuthMode == Basic) && ad.User != "" {
		domain, user, password := ad.AuthDomain, ad.User, ad.Password
		return func() smb2.Initiator {
			return &smb2.NTLMInitiator{Domain: domain, User: user, Password: password}
		}, true
	}
	return nil, false
}

func newSMBPolicyClient(ctx context.Context, server, share string, initiator smb2.Initiator) (*smbPolicyClient, error) {
	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(server, "445"))
	if err != nil {
		return nil, fmt.Errorf("connecting to SMB on %s: %w", server, err)
	}
	session, err := (&smb2.Dialer{Initiator: initiator}).DialConn(ctx, conn, server)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("SMB session setup with %s: %w", server, err)
	}
	mounted, err := session.Mount(share)
	if err != nil {
		_ = session.Logoff()
		_ = conn.Close()
		return nil, fmt.Errorf(`mounting \\%s\%s: %w`, server, share, err)
	}
	return &smbPolicyClient{conn: conn, session: session, share: mounted}, nil
}

func (c *smbPolicyClient) Close() {
	_ = c.share.Umount()
	_ = c.session.Logoff()
	_ = c.conn.Close()
}

// splitUNC splits \\host\share\rest into the share name and the share-relative
// path (forward slashed).
func splitUNC(unc string) (share, rel string, ok bool) {
	parts := strings.SplitN(strings.TrimPrefix(unc, `\\`), `\`, 3)
	if len(parts) < 2 || parts[1] == "" {
		return "", "", false
	}
	if len(parts) == 3 {
		rel = strings.ReplaceAll(parts[2], `\`, "/")
	}
	return parts[1], rel, true
}

// smbPolicySource walks one GPO directory on the mounted share. Every entry gets
// its owner and DACL, like the local collector does on a real SYSVOL path.
type smbPolicySource struct {
	share *smb2.Share
	root  string
}

func (c *smbPolicyClient) source(root string) policySource {
	return smbPolicySource{share: c.share, root: root}
}

func (s smbPolicySource) walk(ctx context.Context, visit func(file *activedirectory.GPOfileinfo, contents *policyContents) error) (basedata.CollectionResults, error) {
	results := make(basedata.CollectionResults)
	stat, err := s.share.Stat(s.root)
	if err != nil {
		results["enumeration"] = basedata.CollectionResultFromError(err)
		file := activedirectory.GPOfileinfo{CollectionResults: results}
		return results, visit(&file, nil)
	}
	var rawSD []byte
	root, err := s.share.Open(s.root)
	if err == nil {
		rawSD, err = root.SecurityInfoRaw(smbSecurityFlags)
		_ = root.Close()
	}
	if err := visit(policyFileInfo("", stat, rawSD, err), nil); err != nil {
		return results, err
	}
	if err := s.walkDir(ctx, "", s.root, visit, results); err != nil {
		return results, err
	}
	if _, exists := results["enumeration"]; !exists {
		results["enumeration"] = basedata.CollectionResultFromError(nil)
	}
	return results, nil
}

// walkDir visits the children of dir; enumeration failures are recorded as data
// and only visitor or context errors abort the walk.
func (s smbPolicySource) walkDir(ctx context.Context, display, dir string, visit func(*activedirectory.GPOfileinfo, *policyContents) error, results basedata.CollectionResults) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := s.share.ReadDirPlus(dir, smbSecurityFlags)
	if err != nil {
		results["enumeration"] = basedata.CollectionResultFromError(err)
		file := activedirectory.GPOfileinfo{RelativePath: display, CollectionResults: basedata.CollectionResults{"enumeration": basedata.CollectionResultFromError(err)}}
		return visit(&file, nil)
	}
	for i := range entries {
		entry := &entries[i]
		name := entry.Name()
		if name == "." || name == ".." {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		childDisplay := display + "/" + name
		childPath := path.Join(dir, name)
		file := policyFileInfo(childDisplay, entry.FileInfo, entry.RawSecurityDescriptor, entry.Err)
		if entry.IsDir() {
			if err := visit(file, nil); err != nil {
				return err
			}
			if err := s.walkDir(ctx, childDisplay, childPath, visit, results); err != nil {
				return err
			}
			continue
		}
		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, ".adm") || strings.HasSuffix(lower, ".admx") {
			if err := visit(file, nil); err != nil {
				return err
			}
			continue
		}
		handle, err := s.share.Open(childPath)
		file.CollectionResults["contents"] = basedata.CollectionResultFromError(err)
		var payload *policyContents
		if err == nil {
			payload = &policyContents{
				reader: handle,
				finalize: func(file *activedirectory.GPOfileinfo, readErr error) {
					file.CollectionResults["contents"] = basedata.CollectionResultFromError(readErr)
				},
			}
		}
		err = visit(file, payload)
		if handle != nil {
			_ = handle.Close()
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func policyFileInfo(display string, stat os.FileInfo, rawSD []byte, sdErr error) *activedirectory.GPOfileinfo {
	file := &activedirectory.GPOfileinfo{RelativePath: display, IsDir: stat.IsDir(), Timestamp: stat.ModTime(), Size: stat.Size(), CollectionResults: make(basedata.CollectionResults)}
	file.CollectionResults["enumeration"] = basedata.CollectionResultFromError(nil)
	file.CollectionResults["metadata"] = basedata.CollectionResultFromError(nil)
	if sdErr == nil {
		file.OwnerSID, file.DACL, sdErr = ownerAndDACL(rawSD)
	}
	file.CollectionResults["security"] = basedata.CollectionResultFromError(sdErr)
	file.CollectionResults["contents"] = basedata.CollectionResult{Status: basedata.CollectionNotRequested}
	return file
}

// ownerAndDACL extracts the owner SID and the raw DACL from a self-relative
// SECURITY_DESCRIPTOR, in the same form windowssecurity.GetOwnerAndDACL returns
// them (the DACL as its ACL structure bytes).
func ownerAndDACL(sd []byte) (windowssecurity.SID, []byte, error) {
	if len(sd) < 20 {
		return "", nil, errors.New("security descriptor too short")
	}
	ownerOffset := binary.LittleEndian.Uint32(sd[4:8])
	daclOffset := binary.LittleEndian.Uint32(sd[16:20])
	if ownerOffset == 0 || int(ownerOffset) >= len(sd) {
		return "", nil, errors.New("security descriptor has no valid owner")
	}
	owner, _, err := windowssecurity.BytesToSID(sd[ownerOffset:])
	if err != nil {
		return "", nil, fmt.Errorf("owner: %w", err)
	}
	if daclOffset == 0 {
		return owner, nil, nil
	}
	if int(daclOffset)+8 > len(sd) {
		return owner, nil, errors.New("DACL offset out of range")
	}
	size := int(binary.LittleEndian.Uint16(sd[daclOffset+2 : daclOffset+4]))
	if size < 8 || int(daclOffset)+size > len(sd) {
		return owner, nil, errors.New("DACL size out of range")
	}
	return owner, append([]byte(nil), sd[daclOffset:int(daclOffset)+size]...), nil
}
