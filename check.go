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

// ReST check
func checkHandler(w http.ResponseWriter, r *http.Request) {
	lg.Printf("RESTful request from %s\n", r.RemoteAddr)

	vars := mux.Vars(r)
	zone := vars["domain"]
	u := unbound.New()
	defer u.Destroy()
	setupUnbound(u)
	result := unboundcheck(u, zone, "NS")
	o := csv.NewWriter(w)
	if e := o.Write(result.serialize()); e != nil {
		lg.Printf("Failed to write csv: %s\n", e.Error())
	}
	lg.Printf("%v from %s\n", result, r.RemoteAddr)
	o.Flush()
}

// ReST check with a type (copied checkHandler because the functions are small)
func checkHandlerType(w http.ResponseWriter, r *http.Request) {
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
				// Nu is het zat...!
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
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
	<head>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
	<title>SIDN Labs Portfolio Checker</title>
	<link rel="shortcut icon" type="image/x-icon" href="http://sidnlabs.nl/favicon.ico">
	<link href="http://www.sidnlabs.nl/fileadmin/sidnlabs/css/all.css" rel="stylesheet" charset="utf-8" type="text/css">
	<style type="text/css" media="screen">
.portfolio {
	margin-left: 20%;
	margin-right; 20%;
	width: 60%;
}
dt {
	font-weight: bold;
}
	</style>
	</head>
	<body>
	<div id="header">
		<div class="holder">
			<div class="logolink"><h1 class="logo"><a href="http://sidnlabs.nl">SIDN Labs een kijkje achter de schermen</a></h1></div>
			<div class="navigation"><ul id="nav"><li><a href="http://www.sidnlabs.nl/over-sidn-labs/" onfocus="blurLink(this)">OVER SIDN LABS</a></li><li><a href="http://www.sidnlabs.nl/contact/" onfocus="blurLink(this)">CONTACT</a></li><li><a href="http://www.werkenbijsidn.nl/" onfocus="blurLink(this)">WERKEN BIJ SIDN</a></li><li><a href="http://www.sidn.nl" onfocus="blurLink(this)">NAAR SIDN.NL</a></li> <li><a href="http://www.sidnlabs.nl/dns-tools/" onfocus="blurLink(this)">DNS TOOLS</a></li> </ul></div>
		</div>
	</div>
	<div id="wrapper">
	<div id="canvas">
	<p>&nbsp;</p>
	<p>&nbsp;</p>
	<p>&nbsp;</p>
	<div class="portfolio">
	<div class="pagetitle"><h1>SIDN Labs Portfolio Checker</h1></div>
	<p>&nbsp;</p>
	</div>

	<div class="portfolio">

Als je een flink aantal domeinnamen hebt en je wilt deze beveiligen met <a href="http://www.dnssec.nl">DNSSEC</a>,
dan bestaat altijd het gevaar dat je een paar details over het hoofd ziet en
niet alle domeinen correct gesigned zijn. SIDN Labs heeft daarom de <a href="http://check.sidnlabs.nl:8080/form">DNSSEC
Portfolio Checker</a> ontwikkeld, waarmee je dit op een snelle en eenvoudige manier
kunt controleren.

	<div class="pagetitle"><h2>Selecteer een <em>CSV</em> bestand met domeinnamen</h2></div>
	
	<form action="http://check.sidnlabs.nl:8080/upload" method="POST" enctype="multipart/form-data">
	<input type="file" name="domainlist">
	<input type="submit" value="Controleer">
	</form>
	
	</div>

	<div class="portfolio">
	<div class="pagetitle"><h2>FAQ</h2></div>
	<dl>
	<dt>Hoe wordt er gecontroleerd?</dt>
	<dd>Je uploadt een CSV bestand met domein namen. Alle namen worden gecontroleerd, dus ook niet-.nl domein namen. Er is een
	limiet ingesteld van 10000 domein namen (per run).
	<p/>
	Er wordt een secure lookup via <a href="http://www.unbound.net">Unbound</a> uitgevoerd. De query zelf vraagt om NS records.
	Er zal een <em>willekeurige</em> selectie van nameservers
	plaatsvinden. Er is geen garantie dat al je slave nameservers worden gecheckt.</dd>

	<dt>Hoe ziet de uitvoer eruit?</dt>
	<dd>De uitvoer van deze check is:
	<p>
	<code>
		domeinnaam, DNS error, security status, uitgebreide error als bogus
	</code>
	</p>

	De security status kan zijn:
	<ul>
	<li><b>secure</b>: de domein naam is correct beveiligd met DNSSEC</li>
	<li><b>bogus</b>: de domein naam is <em>niet</em> correct beveiligd met DNSSEC</li>
	<li><b>insecure</b>: de domein naam is niet beveiligd met DNSSEC</li>
	</ul>
	<p>
	Er kunnen legio oorzaken zijn als een domein <em>bogus</em> is. De error text van Unbound is
	over het algemeen heel leesbaar.
	<p/>
	De DNS error is <b>nodata</b> als Unbound geen informatie kan vinden in het DNS.
	<p/>
	De uitvoer is gesorteerd op de security status, dus alle <em>b</em>ogus domeinen komen vooraan te staan.

	</dd>

	<dt>Kan er ook een enkele domein naam worden gecontroleerd?</dt>
	<dd>Uiteraard is dat mogelijk door een bestand te uploaden dat maar 1 domein naam bevat. Of je kunt
	de volgende URL gebruiken die een RESTful-achtige interface aanbiedt:
	<p>
	<a href="http://check.sidnlabs.nl:8080/check/">check.sidnlabs.nl:8080/check/domeinnaam</a>
	</p>
	Bv: 
	<a href="http://check.sidnlabs.nl:8080/check/example.nl">check.sidnlabs.nl:8080/check/example.nl</a>
	<p>
	Ook hier wordt om de NS records gevraagd. De uitvoer daarvan is gelijk aan de Portfolio-Checker uitvoer (CSV).
	</p>
	<p>
	Optioneel kan aan de RESTful interface ook een DNS type worden meegeven, zodat er om iets anders gevraagd wordt
	dan een NS record. Die interface werkt als volgt:
	<p>
	<a href="http://check.sidnlabs.nl:8080/check/">check.sidnlabs.nl:8080/check/domeinnaam/type</a>
	</p>
	Bv: 
	<a href="http://check.sidnlabs.nl:8080/check/example.nl">check.sidnlabs.nl:8080/check/example.nl/SOA</a>
	<p>
	De lijst van DNS types die gebruikt kunnen worden is: SOA, A, NS, MX, TXT, AAAA, SRV, DS en DNSKEY .
	De uitvoer daarvan is gelijk aan de Portfolio-Checker uitvoer (CSV).
	</p>

	<dt>Welke software wordt gebruikt?</dt>
	<dd>Deze Portfolio Checker gebruikt:
	<ul>
		<li>Libunbound van <a href="http://www.nlnetlabs.nl">NLnet Labs</a></li>
		<li>De taal <a href="http://www.golang.org">Go</a></li>
	</ul>
	De software zelf is open source en is te vinden op <a href="http://github.com/SIDN/unboundcheck">github.com/SIDN/unboundcheck</a>.
	De gebruikte packages zijn <a href="http://github.com/miekg/dns">github.com/miekg/dns</a> en 
	<a href="http://github.com/miekg/unbound">github.com/miekg/unbound</a>.
	</dd>
	</dl>
	</div>

	<div class="portfolio">
	<div class="pagetitle"><h2>Disclaimer</h2></div>
	<p>
	Dit is beta software! De software wordt <em>expliciet</em> niet ondersteund door SIDN, maar door SIDN Labs. 
	Neem bij problemen met het gebruik van deze software contact op met miek.gieben@sidn.nl of @miekg op twitter.
	</p>
	<p>
	SIDN zal de Portfolio Checker zelf gebruiken
	voor statistische doeleinden (% errors in de .nl-zone, etc.), maar geen data
	publiceren over individuele domeinnamen of registrars.
	</p>
	<p>&nbsp;</p>
	</div>

	</div> <!-- canvas -->
	</div> <!-- wrapper -->
	</body>
</html>`)
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
func setupUnbound(u *unbound.Unbound) {
	u.ResolvConf("/etc/resolv.conf")
	u.AddTa(`;; ANSWER SECTION:
.                       168307 IN DNSKEY 257 3 8 (
                                AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQ
                                bSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh
                                /RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWA
                                JQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXp
                                oY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3
                                LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGO
                                Yl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGc
                                LmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=
                                ) ; key id = 19036`)
}
