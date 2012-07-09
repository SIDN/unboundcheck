package main

import (
	"code.google.com/p/gorilla/mux"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net/http"
	"unbound"
)

func CheckHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Hello")
	vars := mux.Vars(r)
	zone := vars["domain"]
	ds := vars["ds"]
	log.Printf("%s: %s", zone, ds)

	u := unbound.New()
	defer u.Destroy()
	if err := setupUnbound(u); err != nil {
		log.Printf("error %s\n", err.Error())
		log.Printf("error %s\n", err.Error())
		return
	}
	// As for NS, so we can use these later on
	res, err := u.Resolve(zone, dns.TypeNS, dns.ClassINET)
	if err != nil {
		log.Printf("error %s\n", err.Error())
		log.Printf("error %s\n", err.Error())
		return
	}

	if res.HaveData {
		if res.Secure {
			log.Printf("Result is secure\n")
			fmt.Fprintf(w, "Result is secure\n")
		} else if res.Bogus {
			log.Printf("Result is bogus: %s\n", res.WhyBogus)
			fmt.Fprintf(w, "Result is bogus: %s\n", res.WhyBogus)
		} else {
			log.Printf("Result is insecure\n")
			fmt.Fprintf(w, "Result is insecure\n")
		}
	} else {
		println("NO DATA")
		return
	}

	u1 := unbound.New()
	setupUnbound(u1)
	if err := u1.AddTa(ds); err != nil {
		log.Printf("error %s\n", err.Error())
		fmt.Fprintf(w, "error %s\n", err.Error())
		return
	}

	res, err = u1.Resolve(zone, dns.TypeNS, dns.ClassINET)
	if err != nil {
		log.Printf("error %s\n", err.Error())
		fmt.Fprintf(w, "error %s\n", err.Error())
		return
	}
	if res.HaveData {
		if res.Secure {
			log.Printf("Result is secure\n")
			fmt.Fprintf(w, "Result is secure\n")
		} else if res.Bogus {
			log.Printf("Result is bogus: %s\n", res.WhyBogus)
			fmt.Fprintf(w, "Result is bogus: %s\n", res.WhyBogus)
		} else {
			log.Printf("Result is insecure\n")
			fmt.Fprintf(w, "Result is insecure\n")
		}
	} else {
		log.Printf("NO DATA")
		fmt.Fprintf(w, "NO DATA")
		return
	}
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/check/{domain}/{ds}", CheckHandler)

	http.Handle("/", router)

	e := http.ListenAndServe(":8080", nil)
	if e != nil {
		log.Fatal("ListenAndServe: ", e)
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
