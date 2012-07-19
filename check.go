package main

import (
	"code.google.com/p/gorilla/mux"
	"encoding/csv"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net/http"
	"sort"
	"strings"
	"unbound"
)

type result struct {
	name   string // name to be checked
	err    string // error from unbound (if any)
	status string // security status
	why    string // WhyBogus from unbound (DNSSEC error)
	dnsviz string // link to dnsviz for further checking
}

type AllResults struct {
	r []*result
}

func NewAllResults() *AllResults {
	a := new(AllResults)
	a.r = make([]*result, 0)
	return a
}

func (a *AllResults) Append(r *result) { a.r = append(a.r, r) }
func (a *AllResults) Len() int         { return len(a.r) }

// Sort on status (bogus is with a 'b' so it will end up first)
func (a *AllResults) Less(i, j int) bool { return a.r[i].status < a.r[j].status }
func (a *AllResults) Swap(i, j int)      { a.r[i], a.r[j] = a.r[j], a.r[i] }

// Create a string slice from *result
func (r *result) serialize() []string {
	if r != nil {
		s := make([]string, 5)
		s[0] = r.name
		s[1] = r.err
		s[2] = r.status
		s[3] = r.why
		s[4] = r.dnsviz
		return s
	}
	return nil
}

// Create HTML from *result
func (r *result) serializeToHTML() {
	// ...
}

func preCheckHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Hello")
	vars := mux.Vars(r)
	zone := vars["domain"]
	trust := vars["trust"]
	log.Printf("%s: %s", zone, trust)

	u := unbound.New()
	defer u.Destroy()
	setupUnbound(u)
	res, err := u.Resolve(zone, dns.TypeNS, dns.ClassINET)
	if err != nil {
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
	if err := u1.AddTa(trust); err != nil {
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

// Output html
func unboundcheck(u *unbound.Unbound, zone string) *result {
	zone = strings.TrimSpace(zone)
	r := new(result)
	r.name = zone
	r.dnsviz = "http://dnsviz.net/d/" + zone + "/dnssec/"
	res, err := u.Resolve(zone, dns.TypeNS, dns.ClassINET)
	log.Printf("checking %s\n", zone)
	if err != nil {
		r.err = err.Error()
		return r
	}
	if res.HaveData {
		if res.Secure {
			r.status = "secure"
		} else if res.Bogus {
			r.status = "bogus"
			r.why = res.WhyBogus
		} else {
			r.status = "insecure"
		}
	} else {
		r.err = "nodata"
	}
	return r
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	zone := vars["domain"]

	u := unbound.New()
	defer u.Destroy()
	setupUnbound(u)
	result := unboundcheck(u, zone)
	fmt.Fprintf(w, "%+v\n", result)
}

func parseHandlerCSV(w http.ResponseWriter, r *http.Request) {
	f, _, err := r.FormFile("domainlist")
	if err != nil {
		fmt.Println(err)
		return
	}
	u := unbound.New()
	defer u.Destroy()
	setupUnbound(u)

	v := csv.NewReader(f)
	o := csv.NewWriter(w)
	record, err := v.Read()
	all := NewAllResults()
	for err == nil {
		for _, r := range record {
			result := unboundcheck(u, r)
			log.Printf("%v\n", result)
			all.Append(result)
		}
		record, err = v.Read()
	}
	sort.Sort(all)
	for _, r := range all.r {
		if e := o.Write(r.serialize()); e != nil {
			log.Printf("Failed to write csv: %s\n", e.Error())
		}
		o.Flush()
	}
}

func form(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `
<html>
	<head>
	<title>Portfolio check</title>
	</head>
	<body>
	<p>Selecteer een <em>CSV</em> bestand met domein namen:</p>
	<form action="http://localhost:8080/upload" method="POST" enctype="multipart/form-data">
	<input type="file" name="domainlist">
	<input type="submit" value="Controleer">
	</form>
	</body>
</html>`)
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/precheck/{domain}/{anchor}", preCheckHandler)
	router.HandleFunc("/check/{domain}", checkHandler)
	router.HandleFunc("/upload", parseHandlerCSV)
	router.HandleFunc("/form", form)
	http.Handle("/", router)

	e := http.ListenAndServe(":8080", nil)
	if e != nil {
		log.Fatal("ListenAndServe: ", e)
	}
}

func setupUnbound(u *unbound.Unbound) {
	u.ResolvConf("/etc/resolv.conf")
	u.AddTaFile("Kroot.key")
}
