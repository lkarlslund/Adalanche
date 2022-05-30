module github.com/lkarlslund/adalanche

go 1.18

require (
	github.com/Microsoft/go-winio v0.5.2
	github.com/OneOfOne/xxhash v1.2.8
	github.com/Showmax/go-fqdn v1.0.0
	github.com/absfs/gofs v0.0.0-20210326223041-415ec8094056
	github.com/absfs/osfs v0.0.0-20210816191758-403afc5396f8
	github.com/antchfx/xmlquery v1.3.9
	github.com/gin-gonic/gin v1.7.7
	github.com/go-asn1-ber/asn1-ber v1.5.3
	github.com/go-ini/ini v1.66.4
	github.com/gobwas/glob v0.2.3
	github.com/gofrs/uuid v4.2.0+incompatible
	github.com/gorilla/mux v1.8.0
	github.com/gravwell/gravwell/v3 v3.8.2 // DONT UPGRADE FROM 3.8.2 - breaks 32-bit builds
	github.com/icza/gox v0.0.0-20210726201659-cd40a3f8d324
	github.com/json-iterator/go v1.1.12
	github.com/lkarlslund/go-win64api v0.0.0-20211005130710-d4f2d07ed091
	github.com/lkarlslund/ldap/v3 v3.2.4-0.20210621153959-85555023df29
	github.com/lkarlslund/stringdedup v0.5.0
	github.com/lkarlslund/time-timespan v0.0.0-20210712111050-6e7c565fa001
	github.com/mailru/easyjson v0.7.7
	github.com/mattn/go-colorable v0.1.12
	github.com/pierrec/lz4/v4 v4.1.14
	github.com/pkg/errors v0.9.1
	github.com/rs/zerolog v1.26.1
	github.com/schollz/progressbar/v3 v3.8.6
	github.com/shirou/gopsutil/v3 v3.22.2
	github.com/spf13/cobra v1.3.0
	github.com/tinylib/msgp v1.1.6
	golang.org/x/sys v0.0.0-20220307203707-22a9840ba4d7
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211
	golang.org/x/text v0.3.7
	github.com/Azure/go-ntlmssp v0.0.0-20211209120228-48547f28849e // indirect
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/absfs/absfs v0.0.0-20200602175035-e49edc9fef15 // indirect
	github.com/alexbrainman/sspi v0.0.0-20210105120005-909beea2cc74 // indirect
	github.com/amidaware/taskmaster v0.0.0-20220111015025-c9cd178bbbf2 // indirect
	github.com/antchfx/xpath v1.2.0 // indirect
	github.com/asergeyev/nradix v0.0.0-20170505151046-3872ab85bb56 // indirect
	github.com/buger/jsonparser v1.1.1 // indirect
	github.com/capnspacehook/taskmaster v0.0.0-20210519235353-1629df7c85e9 // indirect
	github.com/cloudflare/buffer v0.0.0-20190408164202-7cab898e1166 // indirect
	github.com/crewjam/rfc5424 v0.1.0 // indirect
	github.com/dchest/safefile v0.0.0-20151022103144-855e8d98f185 // indirect
	github.com/dlclark/regexp2 v1.4.1-0.20201116162257-a2a8dda75c91 // indirect
	github.com/dop251/goja v0.0.0-20220214123719-b09a6bfa842f // indirect
	github.com/dop251/goja_nodejs v0.0.0-20211022123610-8dd9abb0616d // indirect
	github.com/elastic/beats v7.6.2+incompatible // indirect
	github.com/elastic/go-sysinfo v1.7.1 // indirect
	github.com/elastic/go-ucfg v0.8.4 // indirect
	github.com/elastic/go-windows v1.0.0 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-playground/locales v0.14.0 // indirect
	github.com/go-playground/universal-translator v0.18.0 // indirect
	github.com/go-playground/validator/v10 v10.10.1 // indirect
	github.com/go-sourcemap/sourcemap v2.1.3+incompatible // indirect
	github.com/gofrs/flock v0.8.1 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/aukera v0.0.0-20201117230544-d145c8357fea // indirect
	github.com/google/cabbie v1.0.3 // indirect
	github.com/google/glazier v0.0.0-20220309125052-ca3c88631db6 // indirect
	github.com/google/go-cmp v0.5.7 // indirect
	github.com/google/go-write v0.0.0-20181107114627-56629a6b2542 // indirect
	github.com/google/gopacket v1.1.17 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/renameio v0.1.0 // indirect; DONT CHANGE FROM v0.1.0
	github.com/google/subcommands v1.2.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/gravwell/gcfg v1.2.9-0.20210818172109-3d05a45a2665 // indirect
	github.com/gravwell/ipfix v1.4.3 // indirect
	github.com/h2non/filetype v1.0.10 // indirect
	github.com/iamacarpet/go-win64api v0.0.0-20210311141720-fe38760bed28 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/inhies/go-bytesize v0.0.0-20210819104631-275770b98743 // indirect
	github.com/joeshaw/multierror v0.0.0-20140124173710-69b34d4ec901 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/jstemmer/go-junit-report v0.9.1 // indirect
	github.com/k-sone/ipmigo v0.0.0-20190922011749-b22c7a70e949 // indirect
	github.com/klauspost/compress v1.15.0 // indirect
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/lkarlslund/binstruct v1.3.1-0.20220418073417-7618823b3136 // indirect
	github.com/magefile/mage v1.12.1 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/miekg/dns v1.1.43 // indirect
	github.com/minio/highwayhash v1.0.2 // indirect
	github.com/mitchellh/colorstring v0.0.0-20190213212951-d06e56a500db // indirect
	github.com/mitchellh/hashstructure v1.1.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d // indirect
	github.com/open-networks/go-msgraph v0.0.0-20200217121338-a7bf31e9c1f2 // indirect
	github.com/open2b/scriggo v0.52.2 // indirect
	github.com/philhofer/fwd v1.1.1 // indirect
	github.com/prometheus/procfs v0.0.8 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20190826022208-cac0b30c2563 // indirect
	github.com/rickb777/date v1.14.2 // indirect
	github.com/rickb777/plural v1.2.2 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/scjalliance/comshim v0.0.0-20190308082608-cf06d2532c4e // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tealeg/xlsx v1.0.5 // indirect
	github.com/tklauser/go-sysconf v0.3.10 // indirect
	github.com/tklauser/numcpus v0.4.0 // indirect
	github.com/ugorji/go/codec v1.2.7 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.17.0 // indirect
	golang.org/x/crypto v0.0.0-20220307211146-efcb8507fb70 // indirect
	golang.org/x/mod v0.6.0-dev.0.20220106191415-9b9b3d81d5e3 // indirect
	golang.org/x/net v0.0.0-20220225172249-27dd8689420f // indirect
	golang.org/x/time v0.0.0-20220224211638-0e9765cccd65 // indirect
	golang.org/x/tools v0.1.10 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/fsnotify.v1 v1.4.7 // indirect
	gopkg.in/gcfg.v1 v1.2.3 // indirect
	gopkg.in/nullbio/null.v6 v6.0.0-20161116030900-40264a2e6b79 // indirect
	gopkg.in/toast.v1 v1.0.0-20180812000517-0a84660828b2 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	howett.net/plist v0.0.0-20181124034731-591f970eefbb // indirect
	github.com/aloknerurkar/gpool v0.0.0-20220411083022-1c09ad956d39 // indirect
	github.com/dmarkham/enumer v1.5.5 // indirect
	github.com/lkarlslund/stringsplus v0.0.0-20211104080454-45e60fe6edc0 // indirect
	github.com/pascaldekloe/name v1.0.0 // indirect
)
