package main

import (
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"os"
	"unbound"
)

func main() {
	u := unbound.New()
	defer u.Destroy()
	flag.Parse()
	if err := setupUnbound(u); err != nil {
		fmt.Printf("error %s\n", err.Error())
		os.Exit(1)
	}

	// As for NS, so we can use these later on
	r, err := u.Resolve(flag.Arg(0), dns.TypeNS, dns.ClassINET)
	if err != nil {
		fmt.Printf("error %s\n", err.Error())
		os.Exit(1)
	}
	if r.HaveData {
		if r.Secure {
			fmt.Printf("Result is secure\n")
		} else if r.Bogus {
			fmt.Printf("Result is bogus: %s\n", r.WhyBogus)
		} else {
			fmt.Printf("Result is insecure\n")
		}
	} else {
		println("NO DATA")
		os.Exit(1)
	}


	u1 := unbound.New()
	setupUnbound(u1)
	if err := u1.AddTaFile(flag.Arg(1)); err != nil {
		println(err.Error())
	}
	r, err = u1.Resolve(flag.Arg(0), dns.TypeNS, dns.ClassINET)
	if err != nil {
		fmt.Printf("error %s\n", err.Error())
		os.Exit(1)
	}
	if r.HaveData {
		if r.Secure {
			fmt.Printf("Result is secure\n")
		} else if r.Bogus {
			fmt.Printf("Result is bogus: %s\n", r.WhyBogus)
		} else {
			fmt.Printf("Result is insecure\n")
		}
	} else {
		println("NO DATA")
		os.Exit(1)
	}

}

func setupUnbound(u *unbound.Unbound) error {
	if err := u.ResolvConf("/etc/resolv.conf"); err != nil {
		return err
	}
	if err := u.AddTaFile("Kroot.key"); err != nil {
		return err
	}
	return nil
}
