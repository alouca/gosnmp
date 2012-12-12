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

// return just the oids (ie keys) of results_t
func (r results_t) oids() (result []string) {
	for key, _ := range r {
		result = append(result, key)
	}
	return
}

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
	oids_netsnmp := conf.using_netsnmp()

	// uncomment to see oids/values returned by netsnmp
	// for oid, value := range oids_netsnmp {
	// 	log.Printf("%s %s", oid, value)
	// }

	// uncomment to see oids/values returned by gosnmp, when using single
	// oid varbinds
	// conf.get_single_varbinds(oids_netsnmp.oids())
	// log.Println("======================================")

	// uncomment to see oids/values returned by gosnmp, when using random
	// length oid varbinds
	// conf.get_random_varbinds(oids_netsnmp.oids())
	// log.Println("======================================")

	// uncomment to see comparsion between results from netsnmp and
	// gosnmp, when using single oid varbinds
	conf.compare_single_varbinds(oids_netsnmp)
	// log.Println("======================================")

	// uncomment to see comparsion between results from netsnmp and
	// gosnmp, when using random length varbinds
	// conf.compare_random_varbinds(oids_netsnmp)
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
		//log.Printf("|key|val| |%s|%s|\n\n", key, val)

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
func (c Conf) using_netsnmp() (result results_t) {
	result = make(results_t)
	var (
		outb, errb bytes.Buffer
		cmd_str    string
	)

	// snmpbulkwalk
	/////////////////////////////

	if c.bulkwalk {
		// log.Printf("snmpbulkwalk using:\n%+v\n\n", c)
		cmd_str = fmt.Sprintf("\"\"/usr/bin/snmpbulkwalk -Ci -Oq -On -c %s -v %s %s %s\"\"",
			c.community, c.version, c.management_ip, c.walk)
		// uncomment to see command string passed to netsnmp
		//log.Printf("%s\n\n", cmd_str)
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

	// snmpget
	/////////////////////////////

	const MAX_OIDS_SENT = 100
	var oidss []string

	// log.Printf("snmpget using:\n%+v\n\n", c)
	for count, oid := range c.oids {
		if !chunk(count, MAX_OIDS_SENT, len(c.oids)) {
			oidss = append(oidss, oid)
		} else {
			cmd_str = fmt.Sprintf("\"\"/usr/bin/snmpget -Oq -On -c %s -v %s %s %s\"\"",
				c.community, c.version, c.management_ip, strings.Join(oidss, " "))
			// uncomment to see command string passed to netsnmp
			// log.Printf("oidss(%d): %s\n\n", len(oidss), cmd_str)

			cmd := exec.Command("/bin/sh", "-c", cmd_str)
			cmd.Stdout = &outb
			cmd.Stderr = &errb
			cmd.Run() // snmp protocol errors are returned as errors, so ignore err

			for _, line := range strings.Split(outb.String(), "\n") {
				if match, oid, value := extract(line); match {
					// uncomment to see oids and values extracted from netsnmp results
					// log.Printf("|oid|value| |%s|%s|\n", oid, value)
					result[oid] = value
				}
			}

			// handle chunking
			oidss = nil // "truncate" oidss
			oidss = append(oidss, oid)
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

func (c Conf) get_single_varbinds(oids []string) {
	s := gosnmp.GoSnmp{c.management_ip, c.community, c.version, 15 * time.Second, log.New(os.Stderr, "", log.LstdFlags)}

	for _, oid := range oids {
		print_varbinds(s.Get(oid))
	}
}

func (c Conf) get_random_varbinds(oids []string) {
	s := gosnmp.GoSnmp{c.management_ip, c.community, c.version, 15 * time.Second, log.New(os.Stderr, "", log.LstdFlags)}

	r := rand.New(rand.NewSource(42)) // 42 arbitrary seed
	const MAX_OIDS_SENT = 10
	random_count := r.Intn(MAX_OIDS_SENT) + 1
	var count int
	var oidss []string

	for _, oid := range oids {
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
	// can't use chunk() here, as doing random counts,
	// so handle last 'chunk' manually
	log.Println("--------------------------------------------")
	log.Printf("oidss(%d):\n%s", count, strings.Join(oidss, "\n"))
	print_varbinds(s.Get(oidss...))
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
		fd := s.FullDecode(ur)
		for oid, rv := range ur {
			log.Printf("raw_value: %#v\n", rv)
			log.Printf("oid|decode: %s|%#v\n\n", oid, fd[oid])
		}
	}
}

func (c Conf) compare_single_varbinds(oids results_t) {
	s := gosnmp.GoSnmp{c.management_ip, c.community, c.version, 15 * time.Second, log.New(os.Stderr, "", log.LstdFlags)}

	for oid, _ := range oids {
		var fr *gosnmp.FullResult
		net_val := oids[oid]
		net_val_n, _ := strconv.ParseInt(net_val, 10, 64)
		go_val_n := int64(0)

		var go_val string
		ur, err := s.Get(oid)
		if err != nil {
			go_val = fmt.Sprintf("%v", err)
		} else {
			fd := s.FullDecode(ur)
			fr = fd[gosnmp.Oid(oid)]
			if fr != nil {
				go_val = fr.Value.String()
				go_val_n = fr.Value.Integer()
			}
		}

		log.Printf("oid|decode: %s|%#v\n", oid, fr)

		var comp string
		if net_val == go_val {
			comp = ">> SAME STRING  <<"
		} else {
			comp = ">> DIFF STRING  <<"
		}
		log.Printf("%s %60s|N G|%-20s\n", comp, net_val, go_val)

		if net_val_n == go_val_n {
			comp = ">> SAME INTEGER <<"
		} else {
			comp = ">> DIFF INTEGER <<"
		}
		log.Printf("%s %60d|N G|%-20d\n\n", comp, net_val_n, go_val_n)

	}
}

func (c Conf) compare_random_varbinds(oids results_t) {
	//
	// TODO nasty - refactor - lots of repeated code...
	//
	s := gosnmp.GoSnmp{c.management_ip, c.community, c.version, 5 * time.Second, log.New(os.Stderr, "", log.LstdFlags)}

	r := rand.New(rand.NewSource(42)) // 42 arbitrary seed
	const MAX_OIDS_SENT = 100
	random_count := r.Intn(MAX_OIDS_SENT) + 1
	var count int
	var oidss []string
	var go_val string
	var fr *gosnmp.FullResult

	for oid, _ := range oids {
		oidss = append(oidss, oid)
		count++

		if count == random_count {
			ur, geterr := s.Get(oidss...)
			fd := s.FullDecode(ur)

			for _, o := range oidss {
				net_val := oids[o]
				if geterr != nil {
					go_val = fmt.Sprintf("%v", err)
				} else {
					fr = fd[gosnmp.Oid(o)]
					if fr != nil {
						go_val = fmt.Sprintf("%s", fr.Value)
					}
				}
				if net_val != go_val {
					log.Printf("oid|decode: %s|%#v\n\n", o, fr)
					log.Printf("%60s|N G|%-20s\n\n", net_val, go_val)
				}
			}

			oidss = nil // "truncate" oidss
			count = 0
			random_count = r.Intn(MAX_OIDS_SENT) + 1
		}
	}

	// can't use chunk() here, as doing random counts,
	// so handle last 'chunk' manually
	ur, geterr := s.Get(oidss...)
	fd := s.FullDecode(ur)

	for _, o := range oidss {
		net_val := oids[o]
		if geterr != nil {
			go_val = fmt.Sprintf("%v", err)
		} else {
			fr = fd[gosnmp.Oid(o)]
			if fr != nil {
				go_val = fmt.Sprintf("%s", fr.Value)
			}
		}
		if net_val != go_val {
			log.Printf("oid|decode: %s|%#v\n\n", o, fr)
			log.Printf("%60s|N G|%-20s\n\n", net_val, go_val)
		}
	}

	oidss = nil // "truncate" oidss
	count = 0
	random_count = r.Intn(MAX_OIDS_SENT) + 1
}

// die is a generic log and exit error handler
func die(err error) {
	if err != nil {
		debug.PrintStack()
		log.Fatal(err)
	}
}

// chunk - returns true when dividing a slice into chunk_size long,
// including last chunk which may be smaller than chunk_size
func chunk(current_position, chunk_size, slice_length int) bool {
	if current_position == 0 {
		return false
	}
	if current_position%chunk_size == chunk_size-1 {
		return true
	}
	if current_position == slice_length-1 {
		return true
	}
	return false
}
