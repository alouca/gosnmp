package main

// walker.go uses netsnmp and gosnmp to query a device
// for values, then compares the results
//
// use it as a way of testing gosnmp, as well as example code of how to
// use gosnmp. I've haven't use command line options, rather you can
// just un/comment sections of code to tweak behaviour.

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/soniah/gosnmp"
)

const config_path = "config.txt"

type Conf struct {
	management_ip string
	community     string
	version       gosnmp.SnmpVersion
	bulkwalk      bool // if true, we're doing an snmpbulkwalk
	walk          string
	oids          oids_t
}

type (
	results_t map[string]string
	oids_t    []string
)

var (
	// an oid (leading .) followed by whitespace then a value
	oid_val_rx = regexp.MustCompile(`^((?:\.\d+)+)\s+(.*)$`)
	err        error
	s          *gosnmp.GoSnmp
)

// implement Stringer interface for oids_t
func (o oids_t) String() string {
	return strings.Join(o, " ")
}

func main() {
	conf := conf_load()
	oids_netsnmp := conf.netsnmp()

	// uncomment to see oids/values returned by netsnmp
	// for oid, value := range oids_netsnmp {
	// 	log.Printf("%s %s", oid, value)
	// }

	// uncomment to see oids/values returned by gosnmp, when using single
	// oid varbinds
	// conf.get_single_varbinds(oids_netsnmp)
	// log.Println("======================================")

	// uncomment to see oids/values returned by gosnmp, when using random
	// length oid varbinds
	// conf.get_random_varbinds(oids_netsnmp)
	// log.Println("======================================")

	conf.compare_single_varbinds(oids_netsnmp)
}

// load configuration from config_path
func conf_load() (conf Conf) {
	conf = Conf{}

	contents, err := ioutil.ReadFile(config_path)
	if err != nil {
		log.Fatalf("can't read %s. See instructions in 'config.in'\n", config_path)
	}

	lines := strings.Split(string(contents), "\n")
	for _, line := range lines {
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		splits := strings.Split(line, ":")
		key := strings.TrimSpace(splits[0])
		val := strings.TrimSpace(splits[1])
		// uncomment to see each key/val loaded from conf file
		// log.Printf("|key|val| |%s|%s|\n\n", key, val)

		if key == "management_ip" {
			conf.management_ip = val
		} else if key == "community" {
			conf.community = val
		} else if key == "version" {
			if conf.version, err = gosnmp.NewSnmpVersion(val); err != nil {
				log.Fatalln(err)
			}
		} else if key == "walk" {
			conf.bulkwalk = true
			conf.walk = val
		} else if !conf.bulkwalk && key == "oid" {
			conf.oids = append(conf.oids, val)
		}
	}

	return conf
}

// get oid data using netsnmp
func (c Conf) netsnmp() (result results_t) {
	result = make(results_t)
	var (
		outb, errb bytes.Buffer
		cmd_str    string
	)

	if c.bulkwalk {
		// log.Printf("snmpbulkwalk using:\n%+v\n\n", c)
		cmd_str = fmt.Sprintf("\"\"/usr/bin/snmpbulkwalk -Ci -Oq -On -c %s -v %s %s %s\"\"",
			c.community, c.version, c.management_ip, c.walk)
	} else {
		// log.Printf("snmpget using:\n%+v\n\n", c)
		cmd_str = fmt.Sprintf("\"\"/usr/bin/snmpget -Oq -On -c %s -v %s %s %s\"\"",
			c.community, c.version, c.management_ip, c.oids)
	}
	// uncomment to see command string passed to netsnmp
	// log.Printf("%s\n\n", cmd_str)
	cmd := exec.Command("/bin/sh", "-c", cmd_str)
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	if err := cmd.Run(); err != nil {
		log.Fatalf("cmd.Run(): %s\n", err)
	}

	for _, line := range strings.Split(outb.String(), "\n") {
		if match, oid, value := extract(line); match {
			// uncomment to see oids and values extracted from netsnmp results
			// log.Printf("|oid|value| |%s|%s|\n", oid, value)
			result[oid] = value
		}
	}

	return result
}

// extract an oid and value from a line returned by netsnmp
func extract(line string) (match bool, oid string, value string) {
	if matches := oid_val_rx.FindAllStringSubmatch(line, -1); matches != nil {
		match = true
		oid = matches[0][1]
		value = strings.Trim(matches[0][2], "\"")
	}
	return
}

func (c Conf) get_single_varbinds(oids results_t) {
	s = gosnmp.DefaultGoSnmp(c.management_ip)
	s.Timeout = 15 * time.Second
	s.Logger = log.New(os.Stderr, "", log.LstdFlags)

	for oid, _ := range oids {
		log.Printf("oid: %s\n", oid)
		print_varbinds(s.Get(oid))
	}
}

func (c Conf) get_random_varbinds(oids results_t) {
	s = gosnmp.DefaultGoSnmp(c.management_ip)
	s.Logger = log.New(os.Stderr, "", log.LstdFlags)
	s.Timeout = 60 * time.Second

	r := rand.New(rand.NewSource(42)) // 42 arbitrary seed
	const MAX_OIDS_SENT = 10
	random_count := r.Intn(MAX_OIDS_SENT) + 1
	var count int
	var oidss []string

	for oid, _ := range oids {
		oidss = append(oidss, oid)
		count++
		if count == random_count {
			log.Println("--------------------------------------------")
			log.Printf("oidss(%d):\n%s", count, strings.Join(oidss, "\n"))
			print_varbinds(s.Get(oidss...))

			oidss = nil // "truncate" oidss
			count = 0
			random_count = r.Intn(MAX_OIDS_SENT) + 1
		}
	}
}

func print_varbinds(ur gosnmp.UnmarshalResults, an_error error) {
	if an_error != nil {
		// TODO categorise errors in gosnmp
		if strings.Contains(fmt.Sprintf("%s", an_error), "invalid oid") {
			log.Printf("INVALID OID: %s", an_error)
		} else {
			die(an_error)
		}
	} else {
		dr := s.DecodeI(ur)
		for oid, rv := range ur {
			log.Printf("oid|decode: %s|%#v\n", oid, dr[oid])
			log.Printf("raw_value: %#v\n\n", rv)
		}
	}
}

func (c Conf) compare_single_varbinds(oids results_t) {
	s = gosnmp.DefaultGoSnmp(c.management_ip)
	s.Timeout = 15 * time.Second
	s.Logger = log.New(os.Stderr, "", log.LstdFlags)

	for oid, _ := range oids {
		net_val := oids[oid]

		ur, err := s.Get(oid)
		var go_val string
		if err != nil {
			go_val = fmt.Sprintf("%v", err)
		}
		// TODO should use DecodeI here, compare strings to strings
		// and numbers to numbers
		// uncomment to compare DecodeS results
		//go_val = s.DecodeS(ur)[gosnmp.Oid(oid)]
		go_val = strconv.FormatInt(s.DecodeN(ur)[gosnmp.Oid(oid)], 10)

		if net_val != go_val {
			log.Printf("oid: %s\n", oid)
			log.Printf("%60s|N G|%-20s\n\n", net_val, go_val)
		}
	}
}

// die is a generic log and exit error handler
func die(err error) {
	if err != nil {
		debug.PrintStack()
		log.Fatal(err)
	}
}
