package main

import (
	"encoding/csv"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/miekg/dns"
	"github.com/miekg/unbound"
	"log"
	"log/syslog"
	"net/http"
	"sort"
	"strings"
)

var TYPES = map[string]uint16{"SOA": dns.TypeSOA, "A": dns.TypeA, "NS": dns.TypeNS, "MX": dns.TypeMX, "TXT": dns.TypeTXT,
	"AAAA": dns.TypeAAAA, "SRV": dns.TypeSRV, "DS": dns.TypeDS, "DNSKEY": dns.TypeDNSKEY}

var lg *log.Logger

const LIMIT = 10000

type result struct {
	typ    string // type to be checked, default to NS
	name   string // name to be checked
	err    string // error from unbound (if any)
	status string // security status
	why    string // WhyBogus from unbound (DNSSEC error)
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

// Create a string slice from *result for printing
func (r *result) serialize() []string {
	if r != nil {
		s := make([]string, 4)
		s[0] = r.name
		s[1] = r.err
		s[2] = r.status
		s[3] = r.why
		return s
	}
	return nil
}

// Create HTML from *result (not used yet)
func (r *result) serializeToHTML() {
	// ...
}

// Checker that checks if a delegation with these keys would be
// secure when registry adds the DS records. TODO(mg)
func preCheckHandler(w http.ResponseWriter, r *http.Request) {
	return
}

func unboundcheck(u *unbound.Unbound, zone string, typ string) *result {
	var errstr string

	zone = strings.TrimSpace(zone)
	r := new(result)
	r.name = zone
	lg.Printf("checking %s %s\n", zone, typ)
	if zone == "" {
		return r
	}
	dnstype := dns.TypeNS
	r.typ = "NS"
	typ = strings.ToUpper(typ)
	if v, ok := TYPES[typ]; ok {
		dnstype = v
		r.typ = typ
	}
	res, err := u.Resolve(zone, dnstype, dns.ClassINET)
	if err != nil {
		r.err = err.Error()
		return r
	}

	if res.Rcode == 0 {
		errstr = ""
	} else {
		if res.Rcode == 2 {
			errstr = "(servfail)"
		} else {
			if res.Rcode == 3 {
				errstr = "(nxdomain)"
			} else {
				errstr = fmt.Sprintf("(rcode: %d)", res.Rcode)
			}
		}
	}

	r.err = errstr

	if res.HaveData || res.NxDomain {
		if res.Secure {
			r.status = "secure"
		} else if res.Bogus {
			r.status = "bogus"
			r.why = res.WhyBogus
		} else {
			r.status = "insecure"
		}
	} else {
		// r.status = "n/a"
		if errstr != "" {
			errstr = " " + errstr
		}
		r.err = fmt.Sprintf("nodata%s", errstr)
	}

	return r
}

// ReST check
func checkHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain") // force text to prevent XSS

	lg.Printf("RESTful request from %s\n", r.RemoteAddr)

	vars := mux.Vars(r)
	zone := vars["domain"]
	u := unbound.New()
	defer u.Destroy()
	setupUnbound(u)
	result := unboundcheck(u, zone, "A")
	o := csv.NewWriter(w)
	if e := o.Write(result.serialize()); e != nil {
		lg.Printf("Failed to write csv: %s\n", e.Error())
	}
	lg.Printf("%v from %s\n", result, r.RemoteAddr)
	o.Flush()
}

// ReST check with a type (copied checkHandler because the functions are small)
func checkHandlerType(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain") // force text to prevent XSS

	lg.Printf("RESTful request from %s\n", r.RemoteAddr)

	vars := mux.Vars(r)
	zone := vars["domain"]
	typ := vars["type"]
	u := unbound.New()
	defer u.Destroy()
	setupUnbound(u)
	result := unboundcheck(u, zone, typ)
	o := csv.NewWriter(w)
	if e := o.Write(result.serialize()); e != nil {
		lg.Printf("Failed to write csv: %s\n", e.Error())
	}
	lg.Printf("%v from %s\n", result, r.RemoteAddr)
	o.Flush()
}

func parseHandlerCSV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain") // force text to prevent XSS
	lg.Printf("Upload request from %s\n", r.RemoteAddr)

	f, _, err := r.FormFile("domainlist")
	if err != nil {
		lg.Printf("Error opening CSV: %s\n", err.Error())
		fmt.Fprintf(w, "Error opening CSV: %s\n", err.Error())
		return
	}
	u := unbound.New()
	defer u.Destroy()
	setupUnbound(u)

	v := csv.NewReader(f)
	o := csv.NewWriter(w)
	record, err := v.Read()
	all := NewAllResults()
	i := 0
	if err != nil {
		lg.Printf("Malformed CSV: %s ", err.Error())
		fmt.Fprintf(w, "Malformed CSV: %s\n", err.Error())
		return

	}
Check:

	for err == nil {
		for _, r1 := range record {
			result := unboundcheck(u, r1, "NS")
			lg.Printf("%v from %s\n", result, r.RemoteAddr)
			all.Append(result)
			i++
			if i > LIMIT {
				// That's enough...!
				lg.Printf("limit seen")
				break Check
			}
		}
		record, err = v.Read()
	}
	sort.Sort(all)
	for _, r := range all.r {
		if e := o.Write(r.serialize()); e != nil {
			lg.Printf("Failed to write csv: %s\n", e.Error())
		}
		o.Flush()
	}
}

func form(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `
<!DOCTYPE html>
<html lang="nl">
<head>
 <title>SIDN Labs Portfolio Checker</title>
 <meta charset="utf-8">
 <meta name="viewport" content="width=device-width, initial-scale=1">
 <meta name="description" content="SIDN Labs DNSSEC portfolio checker">
 <meta name="keywords" content="DNSSEC check servfail">
 <link type="text/css" rel="stylesheet" href="//check.sidnlabs.nl/portfolio/assets/css/layout.css">
 <link rel="icon" href="//check.sidnlabs.nl/portfolio/favicon.ico">
 <!--  <link rel="icon" type="image/png" sizes="64x64" href="//check.sidnlabs.nl/portfolio/favicon.png"> -->
</head>

<body>
<div class="site">
 <div class="site__content">
  <a class="logo__link" href="//www.sidnlabs.nl/">
   <div class="logo">
    <svg>
        <g fill-rule="nonzero">
            <path d="M63.684 32.03C60.332 21.148 53.62 7.957 49.75.5c3.606.255 6.452.655 9.542 1.48.034 7.378 3.83 20.01 4.392 30.05z" fill="#11bbb9"></path>
            <path d="M.033 38.038V33.57c1.523.73 3.408 1.456 5.462 1.456 2.184 0 3.144-.727 3.144-1.92 0-1.588-1.424-1.62-4.602-3.012C1.952 29.2 0 27.612 0 24.17c0-4.17 3.145-6.09 7.448-6.09 2.283 0 4.137.496 5.296.925v4.37c-1.06-.496-2.98-1.126-4.9-1.126-1.886 0-2.746.63-2.746 1.722 0 1.19 1.125 1.62 3.045 2.316 3.145 1.126 5.892 2.35 5.892 6.587 0 4.204-3.31 6.356-7.614 6.356-2.68 0-4.733-.464-6.387-1.192zM49.98 32.006v-9.238c-8.817-5.75-18.313-11.756-25.742-17.103-2.99 2.72-5.166 7.346-6.132 12.697h5.16v13.66l5.066-.006V18.36h7.514c7.58 0 10.36 4.966 10.36 10.295a12.81 12.81 0 0 1-.44 3.35h4.214z" fill="#1468b3"></path>
            <path d="M58.36 32.016l-3.813-.006v6.97H49.98v-6.974h-4.214c-1.025 3.766-3.982 6.975-10.02 6.975h-7.414v-6.964l-5.065.006v6.96h-5.16c1.172 7.774 4.247 13.073 11.592 15.505 9.558-6.813 21.482-12.01 30.558-19.416l-1.898-3.054z" fill="#f15d2c"></path>
            <path d="M60.258 35.07c-9.076 7.407-21 12.604-30.56 19.417 2.558.933 5.324 1.517 8.464 1.916C45.215 50.05 54.126 44.04 60.788 35.92l-.53-.85z" fill="#e88040"></path>
            <path d="M63.124 38.98h-.432l-1.904-3.06c-6.662 8.12-15.573 14.13-22.626 20.483 8.408.99 16.5.893 23.143-1.406-.63-5.27.933-10.184 1.82-16.016z" fill="#672c91"></path>
            <path d="M65.927 38.98h-2.803c-.886 5.833-2.45 10.747-1.82 16.017 3.6-1.284 5.868-2.883 7.913-5.75-1.992-3.918-2.525-6.985-3.29-10.266z" fill="#1cabce"></path>
            <path d="M68.22 38.16v.82h-2.293c.765 3.282 1.298 6.35 3.29 10.267 1.092-1.54 2.022-3.516 2.686-5.565-1.713-2.268-2.71-3.935-3.684-5.52z" fill="#fff"></path>
            <path d="M73.96 24.246c-2.463 1.17-3.835 3.263-5.74 5.064v8.85c.974 1.587 1.97 3.254 3.683 5.522 1.875-5.877 2.34-12.29 2.057-19.436z" fill="#139849"></path>
            <path d="M73.764 21.342c-2.428 1.757-3.767 4.366-5.545 6.712v1.256c1.905-1.8 3.277-3.895 5.74-5.064-.047-1.06-.1-1.874-.196-2.904z" fill="#fff"></path>
            <path d="M73.04 16.438c-2.21 2.475-3.43 5.662-4.82 8.714v2.902c1.777-2.346 3.116-4.955 5.544-6.712a42.586 42.586 0 0 0-.724-4.904z" fill="#f15d2c"></path>
            <path d="M68.22 25.152c1.39-3.052 2.61-6.24 4.82-8.714-.067-.31-.043-.206-.114-.513-.847-3.68-2.097-6.446-4.254-8.782-1.504 3.202-2.124 7.15-2.615 11.217h2.162v6.792z" fill="#002d6a"></path>
            <path d="M66.057 18.36c.49-4.066 1.11-8.015 2.615-11.217a14.878 14.878 0 0 0-3.076-2.54c-1.195 3.775-1.263 8.69-1.262 13.757h1.723z" fill="#48ba7f"></path>
            <path d="M63.96 18.36c-.14-5.262-.23-10.357.845-14.223-.243-.136-.158-.09-.408-.222-1.008 3.908-.836 9.09-.62 14.445h.183z" fill="#002d6a"></path>
            <path d="M63.65 18.36h.126c-.215-5.355-.387-10.537.62-14.445a22.47 22.47 0 0 0-1.733-.807c-1.008 5.912.58 14.902.988 23.104V18.36z" fill="#48ba7f"></path>
            <path d="M63.65 28.82V26.21c-.407-8.202-1.995-17.192-.987-23.104a27.126 27.126 0 0 0-3.37-1.127c.033 7.378 3.828 20.01 4.39 30.05-.064-.926-.032-2.35-.032-3.21z" fill="#1468b3"></path>
            <path d="M63.684 32.03C60.332 21.148 53.62 7.957 49.75.5a70.317 70.317 0 0 0-7.21-.163c6.34 7.342 14.795 19.42 20.26 29.956.343.63.656 1.245.884 1.737z" fill="#e88040"></path>
            <path d="M42.54.337c-.36.01-.832.025-1.188.04 4.264 4.67 9.353 11.18 13.988 17.983h.102l1.377 2.207 4.47 7.167.01.017.564.905c.31.512.636 1.082.936 1.638C57.335 19.757 48.88 7.68 42.54.337z" fill="#672c91"></path>
            <path d="M55.34 18.36C50.705 11.558 45.616 5.05 41.352.378c-.71.03-1.06.052-1.756.1 4.62 4.713 10.05 11.16 15.008 17.882h.736z" fill="#1cabce"></path>
            <path d="M54.604 18.36C49.644 11.64 44.214 5.19 39.596.48c-1.394.1-2.63.234-3.938.435 5.31 4.778 11.44 11.005 17.098 17.445h1.848z" fill="#139849"></path>
            <path d="M49.98 18.36h2.776C47.096 11.92 40.97 5.693 35.658.915c-2.28.35-4.09.783-5.993 1.5 6.207 4.926 13.483 10.83 20.315 16.79v-.845z" fill="#fff"></path>
            <path d="M49.98 19.206c-6.832-5.96-14.108-11.865-20.315-16.79-1.356.51-2.586 1.13-3.697 1.882 7.1 5.294 15.86 11.368 24.012 17.292v-2.384z" fill="#f15d2c"></path>
            <path d="M49.98 21.59C41.828 15.667 33.068 9.593 25.968 4.3c-.22.15-.148.1-.364.254 7.174 5.314 16.086 11.383 24.376 17.28v-.24z" fill="#002d6a"></path>
            <path d="M64.334 18.36c0-5.068.067-9.982 1.262-13.756a18.92 18.92 0 0 0-.79-.467c-1.075 3.866-.985 8.96-.846 14.223h.374z" fill="#fff"></path>
            <path d="M58.36 32.016l-2.09-3.36c-.56-.882-1.207-1.96-1.65-2.84-.055-.114-.12-.235-.17-.34.003.075.004.156.01.232.034.88.087 1.898.087 2.78v3.522l3.813.006z" fill="#1468b3"></path>
            <path d="M49.98 21.833c-8.29-5.898-17.202-11.967-24.376-17.28-.434.31-.98.755-1.366 1.112 7.43 5.347 16.925 11.353 25.742 17.103v-.935z" fill="#48ba7f"></path>
            <path d="M40.28 32.006l-6.785.006v2.733h1.755c2.875 0 4.34-1.073 5.03-2.74z" fill="#f15d2c"></path>
            <path d="M35.448 22.53h-1.953v9.482l6.784-.006c.388-.94.532-2.095.532-3.35 0-3.51-1.028-6.125-5.364-6.125z" fill="#1468b3"></path>
            <path d="M49.98 21.59v-3.23h5.463l1.372 2.2 4.477 7.175c0 .006.005.01.008.016l.564.904c.31.513.636 1.083.936 1.64.343.63.656 1.244.884 1.736-.065-.926-.033-2.35-.033-3.21V18.36h4.57v20.62H62.69l-1.904-3.06-.53-.85-1.898-3.054-2.09-3.362c-.56-.88-1.206-1.958-1.65-2.84-.055-.112-.12-.233-.17-.337.003.074.004.155.01.23.034.882.087 1.9.087 2.782v10.49H49.98V21.59zM18.106 18.362h5.16v20.62h-5.16zM40.28 32.006c-.69 1.666-2.155 2.74-5.03 2.74h-1.755V22.53h1.953c4.336 0 5.364 2.615 5.364 6.123 0 1.256-.144 2.41-.533 3.35zM35.845 18.36h-7.514v20.62h7.415c6.037 0 8.994-3.208 10.02-6.974a12.81 12.81 0 0 0 .44-3.35c0-5.33-2.782-10.296-10.36-10.296z" fill="#fff"></path>
            <path d="M78.366 20.957H80.8v9.122h4.055v1.952h-6.49V20.957zM92.587 27.874l-.923-2.846c-.214-.658-.427-1.297-.552-1.812h-.035a46.597 46.597 0 0 1-.57 1.812l-.96 2.846h3.04zm-2.773-6.917h2.72l4.052 11.075h-2.648l-.71-2.203h-4.32l-.747 2.202h-2.505l4.16-11.075zM102.133 30.13c1.085 0 1.672-.497 1.672-1.476 0-.995-.552-1.51-1.654-1.51h-1.528v2.987h1.51zm-.052-4.656c1.103 0 1.565-.498 1.565-1.352 0-.765-.48-1.262-1.547-1.262h-1.476v2.614h1.46zm-3.892-4.517h4.212c2.4 0 3.698 1.14 3.698 2.827 0 1.37-.835 2.205-1.743 2.453v.035c1.19.268 2.08 1.104 2.08 2.543 0 2.025-1.53 3.217-3.93 3.217H98.19V20.957zM108.106 31.55v-2.114c.8.373 1.83.746 2.898.746 1.225 0 1.85-.424 1.85-1.243 0-.96-.837-1.066-2.507-1.797-1.14-.513-2.223-1.314-2.223-3.164 0-2.15 1.617-3.164 3.857-3.164 1.193 0 2.206.284 2.775.498v2.062c-.57-.268-1.582-.588-2.596-.588-1.102 0-1.618.41-1.618 1.12 0 .747.622.978 1.742 1.405 1.44.73 3.11 1.05 3.11 3.538 0 2.15-1.688 3.324-3.946 3.324-1.386 0-2.488-.248-3.342-.623z" fill="#1468b3"></path>
        </g>
    </svg>
   </div>
  </a>
 <div class="copy">
<h1>SIDN Labs Portfolio Checker</h1>
Versie 20221123
<br>
Als je een flink aantal domeinnamen hebt en je wilt deze beveiligen met <a href="http://www.dnssec.nl">DNSSEC</a>,
dan bestaat altijd het gevaar dat je een paar details over het hoofd ziet en
niet alle domeinen correct gesigned zijn. SIDN Labs heeft daarom de <a href="form">DNSSEC
portfolio-checker</a> ontwikkeld, waarmee je dit op een snelle en eenvoudige manier
kunt controleren.

<h3>LET OP: De portfoliochecker zal in de loop van 2023 worden uitgefaseerd! Schakel daarom over op een alternatief.</h3>

<h2>Selecteer een <em>CSV</em> bestand met domeinnamen</h2>

<form action="upload" method="POST" enctype="multipart/form-data">
 <input type="file" name="domainlist">
 <input type="submit" value="Controleer">
</form>

<h2>FAQ</h2>
  <dl>
    <dt>Hoe wordt er gecontroleerd?</dt>
     <dd>Je uploadt een CSV bestand met domein namen. Alle namen worden gecontroleerd, dus ook niet-.nl domein namen.
      Er is een limiet ingesteld van 10000 domein namen (per run).
      Er wordt per domeinnaam een DNSSEC-validatie via <a href="http://www.unbound.net">Unbound</a> uitgevoerd.
      De DNS-query vraagt om 'NS'-records. Er zal een <em>willekeurige</em> selectie van nameservers
      plaatsvinden. Er is geen garantie dat al je slave nameservers worden gecheckt. Als er geen NS-records
      zijn, levert dit een 'nodata'-antwoord op.
     </dd>
    <dt>Hoe ziet de uitvoer eruit?</dt>
     <dd>De uitvoer van deze check is:
     <br>
      <code>
	 domeinnaam, DNS error, security status, uitgebreide error indien bogus
      </code>
     <br>
      De security-status kan zijn:
	<ul>
	 <li><b>secure</b>: de domein naam is correct beveiligd met DNSSEC</li>
	 <li><b>bogus</b>: de domein naam is <em>niet</em> correct beveiligd met DNSSEC</li>
	 <li><b>insecure</b>: de domein naam is niet beveiligd met DNSSEC</li>
	</ul>
      Er kunnen legio oorzaken zijn als een domein <em>bogus</em> is. De error text van Unbound is
      bedoeld om hierover opheldering te verschaffen. De DNS-error is <b>nodata</b> als Unbound de
      gevraagde informatie (bijvoorbeeld NS records) niet kan vinden in het DNS.
      De uitvoer is gesorteerd op de security status, dus alle <em>b</em>ogus domeinen komen vooraan te staan.
     </dd>
    <dt>Kan er ook een enkele domein naam worden gecontroleerd?</dt>
     <dd>Uiteraard is dat mogelijk door een bestand te uploaden dat maar &eacute;&eacute;n domein naam bevat. Of je kunt
      een URL gebruiken die een RESTful-achtige interface aanbiedt:
      <br><br>
      Bijvoorbeeld: <a href="check/example.nl">portfolio.sidnlabs.nl/check/www.example.nl</a>
      <br><br>
      LET OP: hier wordt om 'A'-records gevraagd. De uitvoer is gelijk aan de portfolio-checker uitvoer (CSV).
      Optioneel kan aan de RESTful interface ook een DNS recordtype worden meegeven, zodat er om iets anders gevraagd wordt
      dan een A record.
      <br><br>
      Bijvoorbeeld: <a href="check/example.nl/SOA">portfolio.sidnlabs.nl/check/example.nl/TXT</a>
      <br><br>
      De lijst van DNS types die gebruikt kunnen worden is: SOA, A, NS, MX, TXT, AAAA, SRV, DS en DNSKEY .
      De uitvoer daarvan is gelijk aan de portfolio-checker uitvoer (CSV),
     </dd>
    <dt>Welke software wordt gebruikt?</dt>
     <dd>Deze portfolio-checker gebruikt:
       <ul>
         <li>Libunbound van <a href="http://www.nlnetlabs.nl">NLnet Labs</a></li>
	 <li>De taal <a href="http://www.golang.org">Go</a></li>
	</ul>
      De software zelf is open source en is te vinden op <a href="http://github.com/SIDN/unboundcheck">github.com/SIDN/unboundcheck</a>.
      De gebruikte packages zijn <a href="http://github.com/miekg/dns">github.com/miekg/dns</a> en <a href="http://github.com/miekg/unbound">github.com/miekg/unbound</a>.
     </dd>
   </dl>
   <h2>Disclaimer</h2>
   Dit is b&egrave;ta software De software wordt <em>expliciet</em> niet ondersteund door SIDN, maar door SIDN Labs.
   De uitvoer kan op enig moment veranderen. Dus het advies is om voor belangrijk eigen gebruik, zelf de code
   te compileren en deze tool op een eigen systeem te draaien. Eenvoudige installatie-instructies staan op
   <a href="http://github.com/SIDN/unboundcheck">GitHub</a>. Neem bij problemen met het gebruik van deze software
   contact op met SIDN Labs via: <a href="http://www.sidnlabs.nl/over-sidnlabs/">onze informatiepagina</a>.
   SIDN kan de portfolio-checker zelf gebruiken voor statistische doeleinden (% errors in de .nl-zone, etc.),
   maar zal geen data publiceren over registrars.
   </div>
 </div>
</div>
</body>
</html>
`) // end of fmt.Fprint
}

func main() {
	var err error
	lg, err = syslog.NewLogger(syslog.LOG_INFO, log.LstdFlags)
	if err != nil {
		log.Fatal("NewLogger: ", err)
	}
	router := mux.NewRouter()
	router.HandleFunc("/check/{domain}", checkHandler)            // ReST check a domain
	router.HandleFunc("/check/{domain}/{type}", checkHandlerType) // ReST check a domain with a type
	router.HandleFunc("/upload", parseHandlerCSV)
	router.HandleFunc("/form", form)
	http.Handle("/", router)

	e := http.ListenAndServe(":8080", nil)
	if e != nil {
		log.Fatal("ListenAndServe: ", e)
	}
}

// Setup the resolver and add the root's trust anchor
// This one is used for RESTful lookups - they contain detailed errors
func setupUnbound(u *unbound.Unbound) {
	//	u.ResolvConf("/etc/resolv.conf")
	u.AddTa(`;; ANSWER SECTION:
.                        172800 IN DNSKEY 257 3 8 (
                                AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTO
                                iW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN
                                7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5
                                LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8
                                efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7
                                pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLY
                                A4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws
                                9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
                                ) ; KSK; alg = RSASHA256; key id = 20326`)

}
