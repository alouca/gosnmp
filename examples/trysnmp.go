// net-snmp-utils is needed on centos
package main

import (
	"bufio"
	"bytes"
	"encoding/asn1"
	"flag"
	"fmt"
	"github.com/oliveagle/gosnmp"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var (
	cmdCommunity     string
	cmdTarget        string
	cmdOidMid        string
	cmdDebug         bool
	cmdTimeout       int
	cmdRetryLimit    int
	cmdRetryDelayMs  int
	cmdDupFilterSize int
	cmdLookUp        bool
	cmdBulkWalk      bool
	cmdBulkSize      uint
	cmdStream        bool
)

func init() {
	flag.BoolVar(&cmdDebug, "v", false, "Target SNMP Agent")

	flag.StringVar(&cmdTarget, "target", "", "Target SNMP Agent")
	flag.StringVar(&cmdCommunity, "community", "public", "SNMP Community")
	flag.StringVar(&cmdOidMid, "oid", "", "The request OID. Multiple OIDs can be separated by a comma")
	flag.IntVar(&cmdTimeout, "timeout", 300, "Set the timeout in milliseconds, default 30ms")

	flag.BoolVar(&cmdLookUp, "lookup", false, "Lookup oid using snmptranslate.")
	flag.IntVar(&cmdRetryLimit, "retry_limit", 5, "timout retry count limit, default 5.")
	flag.IntVar(&cmdRetryDelayMs, "retry_delay_ms", 100, "timeout retry delay ms, default 100")
	flag.IntVar(&cmdDupFilterSize, "dup_filter_size", 100, "duplicate filter cache size, default 100")
	flag.BoolVar(&cmdBulkWalk, "bulk", false, "bulkwalk or not, default false")
	flag.UintVar(&cmdBulkSize, "bulksize", 50, "bulk size, default 50, no more than 255")
	flag.BoolVar(&cmdStream, "stream", false, "stream way to get response. default false")
	flag.Parse()
}

func methodBulkWalk(s *gosnmp.GoSNMP, oid string) {
	fmt.Println("Bulk Walk", oid)
	res, err := s.BulkWalk(uint8(cmdBulkSize), oid)
	if err != nil {
		fmt.Printf("Error Bulk Walk: %v\n", err)
	}
	for idx, r := range res {
		//			fmt.Printf("(%d) name: %v, t: %v, v: %v\n", idx, r.Name, r.Type, r.Value)
		if oid, err := parseOID(r.Name); err == nil {
			if prefix, suffix, err := TranslateOIDFromCache(oid); err == nil {
				// fmt.Printf("(%d) prefix: %s, suffix: %s -> value: %v (oid:%v)\n", idx, prefix, suffix, r.Value, r.Name)
				fmt.Printf("BulkWalk: (%d) prefix: %s, suffix: %s -> value: %v\n", idx, prefix, suffix, r.Value)
			} else if prefix != "" {
				fmt.Printf("BulkWalk: (%d) prefix: %s, suffix: ---, err: %v -> value: %v\n", idx, prefix, err, r.Value)
			} else {
				fmt.Printf("BulkWalk: (%d) oid: %v -> value: %s  err: %v\n", idx, r.Name, r.Value, err)
			}
		} else {
			fmt.Printf("BulkWalk: ERROR: %v\n", err)
		}
	}
}

func methodStreamBulkWalk(s *gosnmp.GoSNMP, oid string) {
	if resChn, err := s.StreamBulkWalk(uint8(cmdBulkSize), oid); err != nil {
		fmt.Printf("Error Bulk Walk: %v\n", err)
	} else {
		idx := 0
		for resp := range resChn {
			if resp.Err != nil {
				fmt.Printf("Error: %v\n", resp.Err)
			} else {
				idx += 1
				if oid, err := parseOID(resp.PDU.Name); err == nil {
					if prefix, suffix, err := TranslateOIDFromCache(oid); err == nil {
						// fmt.Printf("(%d) prefix: %s, suffix: %s -> value: %v (oid:%v)\n", idx, prefix, suffix, r.Value, r.Name)
						fmt.Printf("StreamBulkWalk: (%d) prefix: %s, suffix: %s -> value: %v\n", idx, prefix, suffix, resp.PDU.Value)
					} else if prefix != "" {
						fmt.Printf("StreamBulkWalk: (%d) prefix: %s, suffix: ---, err: %v -> value: %v\n", idx, prefix, err, resp.PDU.Value)
					} else {
						fmt.Printf("StreamBulkWalk: (%d) oid: %v -> value: %s  err: %v\n", idx, resp.PDU.Name, resp.PDU.Value, err)
					}
				} else {
					fmt.Printf("StreamBulkWalk: ERROR: %v\n", err)
				}
			}
		}
	}
}

func methodStreamWalk(s *gosnmp.GoSNMP, oid string) {
	fmt.Printf("methodStreamWalk: %v\n", oid)
	s.SetErrorDelayMs(cmdRetryDelayMs)
	s.SetRetryCnt(cmdRetryLimit)
	resChn, err := s.StreamWalk(oid, cmdDupFilterSize)
	if err != nil {
		fmt.Printf("Error getting response: %s\n", err.Error())
	} else {
		idx := 0
		for resp := range resChn {
			if resp.Err != nil {
				fmt.Printf("Error: %v\n", resp.Err)
			} else {
				idx += 1
				if oid, err := parseOID(resp.PDU.Name); err == nil {
					if prefix, suffix, err := TranslateOIDFromCache(oid); err == nil {
						fmt.Printf("StreamWalk: (%d) prefix: %s, suffix: %s -> value: %v\n", idx, prefix, suffix, resp.PDU.Value)
					} else if prefix != "" {
						fmt.Printf("StreamWalk: (%d) prefix: %s, suffix: ---, err: %v -> value: %v\n", idx, prefix, err, resp.PDU.Value)
					} else {
						fmt.Printf("StreamWalk: (%d) oid: %v -> value: %v  err: %v\n", idx, resp.PDU.Name, resp.PDU.Value, err)
					}
				} else {
					fmt.Printf("StreamWalk: ERROR: %v\n", err)
				}
			}
		}
	}
}

var cache_prefix = make(map[string]string)
var max_cache_prefix_oid_length = 0
var min_cache_prefix_oid_length = 9999

//var cache_suffix = make(map[string]string{})
var pat_split = regexp.MustCompile(`\s+`)

func BuildIdentifierCaches(mib_file []string) {
	args := []string{"-f", "identifiers", "-k", "-u"}
	for _, x := range mib_file {
		args = append(args, x)
	}
	cmd := exec.Command("smidump", args...)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Run()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		cols := pat_split.Split(scanner.Text(), -1)
		if len(cols) >= 4 {
			if oid, err := parseOID(cols[3]); err == nil {
				if len(oid) > max_cache_prefix_oid_length {
					max_cache_prefix_oid_length = len(oid)
				}
				if len(oid) < min_cache_prefix_oid_length {
					min_cache_prefix_oid_length = len(oid)
				}
				key := asn1.ObjectIdentifier(oid).String()
				value := fmt.Sprintf("%s::%s", cols[0], cols[1])
				cache_prefix[key] = value
			}
		}
	}
}

func TranslateOIDFromCache(oid []int) (string, string, error) {
	if len(oid) < min_cache_prefix_oid_length {
		return "", "", fmt.Errorf("no prefix cache found which length less than %d", min_cache_prefix_oid_length)
	}
	for x := max_cache_prefix_oid_length; x >= min_cache_prefix_oid_length; x-- {
		if len(oid) < x {
			continue
		}
		prefix_oid := oid[:x]
		prefix_oid_s := asn1.ObjectIdentifier(prefix_oid).String()
		if v, ok := cache_prefix[prefix_oid_s]; ok == true {
			if suffix, err := translateSuffix(oid[x:len(oid)]); err == nil {
				return v, suffix, nil
			} else {
				fmt.Println("Error: ", oid)
				return v, "", err
			}
		}
	}
	return "", "", fmt.Errorf("didn't found oid in cache: %s", asn1.ObjectIdentifier(oid).String())
}

func translateSuffix(oid []int) (string, error) {
	if len(oid) <= 0 {
		return "", fmt.Errorf("empty suffix oid")
	}
	if len(oid) == 1 {
		return strconv.Itoa(oid[0]), nil
	}
	b_oid := []byte{}
	for _, i := range oid[1:len(oid)] {
		if i > 255 {
			return "", fmt.Errorf("maybe not ascii string")
		}
		b_oid = append(b_oid, byte(i))
	}
	_oid_s := fmt.Sprintf("%s", b_oid)
	return _oid_s, nil
}

func parseOID(s string) (oid []int, err error) {
	if s == "" {
		return nil, fmt.Errorf("empty oid string")
	}
	if s[0] == '.' {
		s = s[1:]
	}
	var n int
	for _, elem := range strings.Split(s, ".") {
		n, err = strconv.Atoi(elem)
		if err != nil {
			return
		}
		oid = append(oid, n)
	}
	return
}

func main() {
	if cmdTarget == "" || cmdOidMid == "" {
		flag.PrintDefaults()
		return
	}
	if cmdBulkSize > 255 {
		fmt.Println("Bulk size should not > 255. ")
		flag.PrintDefaults()
		return
	}

	s, err := gosnmp.NewGoSNMP(cmdTarget, cmdCommunity, gosnmp.Version2c, cmdTimeout)
	if cmdDebug == true {
		s.SetDebug(true)
		s.SetVerbose(true)
	}
	if err != nil {
		fmt.Printf("Error creating SNMP instance: %s\n", err.Error())
		return
	}
	//	s.SetTimeout(cmdTimeout)
	s.SetTimeoutMs(cmdTimeout)

	cmd_oid := cmdOidMid[:]
	if cmdLookUp {
		if _oid, err := MibLookup(cmd_oid); err == nil {
			fmt.Printf("Lookup(%v) => %v\n", cmdOidMid, _oid.String())
			cmd_oid = _oid.String()
		} else {
			fmt.Printf("Failed to Lookup mib: err: %v, mib: %v\n", err, cmd_oid)
			os.Exit(2)
		}
	}

	// build caches from all mibs will take longer
	//	if files, err := ioutil.ReadDir("/usr/share/snmp/mibs"); err == nil {
	//		for _, fi := range files {
	//			BuildIdentifierCaches([]string{path.Join("/usr/share/snmp/mibs", fi.Name())})
	//		}
	//	} else {
	//		BuildIdentifierCaches([]string{"NS-MIB-smiv2.mib", "/usr/share/snmp/mibs/IPV6-MIB.txt"})
	//	}
	BuildIdentifierCaches([]string{"NS-MIB-smiv2.mib", "/usr/share/snmp/mibs/IPV6-MIB.txt"})
	//	return
	if cmdBulkWalk {
		if cmdStream {
			methodStreamBulkWalk(s, cmd_oid)
		} else {
			methodBulkWalk(s, cmd_oid)
		}
	} else {
		methodStreamWalk(s, cmd_oid)
	}
}

// Lookup looks up the given object prefix using the snmptranslate utility. borrowed from github.com/masiulaniec/snmp/mib
func MibLookup(prefix string) (asn1.ObjectIdentifier, error) {
	cmd := exec.Command(
		"snmptranslate",
		"-Le",
		"-m", "all",
		"-On",
		prefix,
	)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("snmp: Lookup(%q): %q: %s", prefix, cmd.Args, err)
	}
	if stderr.Len() != 0 {
		return nil, fmt.Errorf("snmp: Lookup(%q): %q: %s", prefix, cmd.Args, stderr)
	}
	oid, err := parseOID(strings.TrimSpace(stdout.String()))
	if err != nil {
		return nil, err
	}
	return oid, nil
}
