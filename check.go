package main

import (
	"bufio"
	"code.google.com/p/gorilla/mux"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net/http"
	"unbound"
)

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
func unboundcheck(u *unbound.Unbound, zone string, even bool) (line string) {
	if even {
		line = "<tru class=\"even\">"
	} else {
		line = "<tr class=\"odd\">"
	}
	line += "<td>" + zone + "</td>"
	dnsviz := "<td><a href=\"http://dnsviz.net/d/" + zone + "/dnssec/\">dnsviz</a></td>"

	// As for NS, so we can use these later on
	res, err := u.Resolve(zone, dns.TypeNS, dns.ClassINET)
	if err != nil {
		line += "<td>" + err.Error() + "</td>" + dnsviz
		log.Printf(line + "\n")
		return line + "</tr>"
	} else {

	}

	if res.HaveData {
		if res.Secure {
			line += "<td>secure</td><td></td>" + dnsviz
		} else if res.Bogus {
			line += "<td>bogus</td><td>" + res.WhyBogus + "</td>" + dnsviz
		} else {
			line += "<td>insecure</td><td></td>" + dnsviz
		}
	} else {
		line += "<td>nodata</td><td></td>" + dnsviz
	}
	log.Printf(line + "\n")
	return line + "</tr>"
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	zone := vars["domain"]

	u := unbound.New()
	defer u.Destroy()
	setupUnbound(u)
	fmt.Fprintf(w, unboundcheck(u, zone, false))
}

func upload(w http.ResponseWriter, r *http.Request) {
	f, _, err := r.FormFile("domainlist")
	if err != nil {
		fmt.Println(err)
		return
	}
	u := unbound.New()
	defer u.Destroy()
	setupUnbound(u)
	// Assume line based for now
	b := bufio.NewReader(f)
	line, _, err := b.ReadLine()
	even := false
	fmt.Fprintf(w,`
<html>
	<head>
		<title>Results</title>
	</head>
	<body>
	<table>`)

	for err == nil {
		fmt.Fprintf(w, unboundcheck(u, string(line), even))
		line, _, err = b.ReadLine()
		even = !even
	}
	fmt.Fprintf(w, "</table></body></html>")
}

func form(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `
<html>
	<head>
	<title>Upload</title>
	</head>
	<body>
	<p>Upload a text file with domain names (one name per line):</p>
	<form action="http://miek.nl:8080/upload" method="POST" enctype="multipart/form-data">
	<input type="file" name="domainlist">
	<input type="submit" value="Upload">
	</form>
	</body>
</html>`)
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/precheck/{domain}/{anchor}", preCheckHandler)
	router.HandleFunc("/check/{domain}", checkHandler)
	router.HandleFunc("/upload", upload)
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
