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

	if res.Rcode==0 {
		errstr=""
	} else {
		if res.Rcode==2 {
			errstr="(servfail)"
		} else {
			if res.Rcode==3 {
				errstr="(nxdomain)"
			} else {
				errstr=fmt.Sprintf("(rcode: %d)", res.Rcode)
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
<html class="no-js" lang="nl">
<head>
                           
<title>SIDN Labs Workbench</title>
<meta charset="utf-8" />
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
    <meta name="og:image"       content="https://www.sidn.nl/assets/img/og-image.png" />

<meta name="og:title"       content="SIDN Labs Workbench" />
<meta name="og:description" content="" />
<meta name="description"    content="" />
<meta name="og:site_name"   content="SIDN - Het bedrijf achter .nl" />
<meta name="og:url"         content="https://www.sidn.nl/sidn-labs/projecten" />
<meta name="og:type"        content="website" />
<meta name="og:locale"      content="nl_NL" />

<meta name="twitter:card"           content="summary" />
<meta name="twitter:description"    content="Lees meer op sidn.nl" />
<meta name="twitter:image"          content="http://www.sidn.nl/assets/img/og-image.jpg" />
<meta name="twitter:site"           content="@sidn" />
<meta name="twitter:title"          content="SIDN : 404" />
<meta name="twitter:url"            content="https://www.sidn.nl/sidn-labs/projecten" />

    <meta name="keywords" content="">

      
      
  
          <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />

        <link type="text/css" rel="stylesheet" href="//workbench.sidnlabs.nl/assets/css/layout.css?v2" />

        <meta name="msapplication-square70x70logo"   content="//workbench.sidnlabs.nl/assets/img/favicons/windows-tile-70x70.png" />
    <meta name="msapplication-square150x150logo" content="//workbench.sidnlabs.nl/assets/img/favicons/windows-tile-150x150.png" />
    <meta name="msapplication-square310x310logo" content="//workbench.sidnlabs.nl/assets/img/favicons/windows-tile-310x310.png" />
    <meta name="msapplication-TileImage"         content="//workbench.sidnlabs.nl/assets/img/favicons/windows-tile-144x144.png" />
    <meta name="msapplication-TileColor"         content="#CEE7F3" />
    <link rel="apple-touch-icon-precomposed" sizes="152x152" href="//workbench.sidnlabs.nl/assets/img/favicons/apple-touch-icon-152x152-precomposed.png" />
    <link rel="apple-touch-icon-precomposed" sizes="120x120" href="//workbench.sidnlabs.nl/assets/img/favicons/apple-touch-icon-120x120-precomposed.png" />
    <link rel="apple-touch-icon-precomposed" sizes="76x76"   href="//workbench.sidnlabs.nl/assets/img/favicons/apple-touch-icon-76x76-precomposed.png" />
    <link rel="apple-touch-icon-precomposed" sizes="60x60"   href="//workbench.sidnlabs.nl/assets/img/favicons/apple-touch-icon-60x60-precomposed.png" />
    <link rel="apple-touch-icon-precomposed" sizes="144x144" href="//workbench.sidnlabs.nl/assets/img/favicons/apple-touch-icon-144x144-precomposed.png" />
    <link rel="apple-touch-icon-precomposed" sizes="114x114" href="//workbench.sidnlabs.nl/assets/img/favicons/apple-touch-icon-114x114-precomposed.png" />
    <link rel="apple-touch-icon-precomposed" sizes="72x72"   href="//workbench.sidnlabs.nl/assets/img/favicons/apple-touch-icon-72x72-precomposed.png" />
    <link rel="apple-touch-icon"             sizes="57x57"   href="//workbench.sidnlabs.nl/assets/img/favicons/apple-touch-icon.png" />
    <link rel="icon"                         sizes="228x228" href="//workbench.sidnlabs.nl/assets/img/favicons/coast-icon-228x228.png" />
    <link rel="shortcut icon"                                href="//workbench.sidnlabs.nl/assets/img/favicons/favicon.ico" />
    <link rel="icon" type="image/png"        sizes="64x64"   href="//workbench.sidnlabs.nl/assets/img/favicons/favicon.png" />

    </head>

<body>
    <div class="media--linkedin"><img src="//workbench.sidnlabs.nl/assets/img/og-image--linkedin.png" alt="" title="" /></div>
    <nav class="pushy pushy-right"></nav>
    <div class="site__overlay"></div>
    <div class="site theme--undefined">
        <div class="site__header">
                              
  
      
              
        
          <div class="container">
      
  
      
    
        
            
  
              	    	    		  		  	  	  		  		  		  	      
    
        
          
      
      
  
    
  
              	    	    		  		  	  	  		  		  		  	      
    
        
          
      
      
  
                                                                  
<div class="site__navigation">

    <div class="logo logo--sidnlabs">
        <a class="logo__link logo__link--sidnlabs" href="/">
            <svg class="icon logo__icon logo__icon--sidnlabs">
                <use xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="//workbench.sidnlabs.nl/assets/img/icons.svg#icon--sidnlabs-logo--fc">
                </use>
            </svg>
        </a>
    </div>

    <div class="site__navigation-container">

        <div class="nav nav--primary">
            <nav role="nav">
                <ul class="nav__list nav__list--primary">
                                            <li class="nav__list-item nav__list-item--primary " >
                                                            <a class="nav__link nav__link--primary" href="//sidn.nl/t/nl-domeinnaam">.nl-domeinnaam</a>
                                                    </li>
                                            <li class="nav__list-item nav__list-item--primary " >
                                                            <a class="nav__link nav__link--primary" href="//sidn.nl/t/diensten">Diensten</a>
                                                    </li>
                                            <li class="nav__list-item nav__list-item--primary " >
                                                            <a class="nav__link nav__link--primary" href="//sidn.nl/t/veilig-internet">Veilig internet</a>
                                                    </li>
                                            <li class="nav__list-item nav__list-item--primary " >
                                                            <a class="nav__link nav__link--primary" href="//sidn.nl/t/kennis-en-ontwikkeling">Kennis en ontwikkeling</a>
                                                    </li>
                                            <li class="nav__list-item nav__list-item--primary " >
                                                            <a class="nav__link nav__link--primary" href="https://www.sidnlabs.nl">SIDN Labs</a>
                                                    </li>
                                            <li class="nav__list-item nav__list-item--primary " >
                                                            <a class="nav__link nav__link--primary" href="//sidn.nl/t/over-sidn">Over SIDN</a>
                                                    </li>
                                    </ul>
            </nav>
        </div>

        <div class="nav nav--secondary">
            <nav role="nav">
                <ul class="nav__list nav__list--secondary">
                    <li class="nav__list-item nav__list-item--secondary"></li>
                </ul>
            </nav>
        </div>

    </div>

    <div class="nav nav--trigger">
        <nav>
            <ul class="nav__list nav__list--trigger">
                <li class="nav__list-item nav__list-item--trigger">
                    <a class="nav__link nav__link--trigger" href="//sidn.nl/whois" data-search-toggle="domains" data-target="domains">
                         <svg class="icon">
    <use xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="//workbench.sidnlabs.nl/assets/img/icons.svg#icon--whois"></use>
</svg>
                        <span class="nav__title nav__title--trigger">form.label.whois</span>
                    </a>
                </li>
                <li class="nav__list-item nav__list-item--trigger">
                    <a class="nav__link nav__link--trigger" href="//sidn.nl/zoeken/" data-search-toggle="site" data-target="site">
                         <svg class="icon">
    <use xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="//workbench.sidnlabs.nl/assets/img/icons.svg#icon--search"></use>
</svg>
                        <span class="nav__title nav__title--trigger">Zoeken</span>
                    </a>
                </li>
                <li class="nav__list-item nav__list-item--trigger">
                    <a class="nav__link nav__link--trigger" href="#" id="nav__trigger">
                         <svg class="icon">
    <use xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="//workbench.sidnlabs.nl/assets/img/icons.svg#icon--menu"></use>
</svg>
                        <span class="nav__title nav__title--trigger">Mobiele navigatie</span>
                    </a>
                </li>
            </ul>
        </nav>
    </div>
</div>


      
      
  
  </div>

      
      
  
                          <div class="search-bar">
                <div class="container">
                      
  
      
    
        
          <div class="search search--site" id="search--site">
    <form class="search__form search__form--site" action="/search" method="get">
        <fieldset>
            <legend class="search__legend">Zoek in sidn.nl</legend>
             <svg class="icon search__icon search__icon--search">
    <use xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="//workbench.sidnlabs.nl/assets/img/icons.svg#icon--search--simple"></use>
</svg>
            <input class="search__input search__input--site" type="search" placeholder="Zoek in sidn.nl" value="" name="q" />
            <button class="search__button search__button--site">
                 <svg class="icon search__icon search__icon--submit">
    <use xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="//workbench.sidnlabs.nl/assets/img/icons.svg#icon--ok"></use>
</svg>
                <span class="button__label">Zoek</span>
            </button>
        </fieldset>
    </form>
</div>

      
      
  
                        
  
      
    
        
          <div class="search search--domains" id="search--domains">
    <form class="search__form search__form--domains" method="get" action="/whois" id="search__form--domains">
        <fieldset>
            <legend class="search__legend">whois.label.legend</legend>
             <svg class="icon search__icon search__icon--domains">
    <use xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="//workbench.sidnlabs.nl/assets/img/icons.svg#icon--whois"></use>
</svg>
            <input class="search__input search__input--domains" autocomplete="off" type="search" placeholder="Check hier je .nl-domeinnaam" value="" name="q" required/>
            <button class="search__button search__button--domains">
                 <svg class="icon search__icon search__icon--submit">
    <use xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="//workbench.sidnlabs.nl/assets/img/icons.svg#icon--ok"></use>
</svg>
                <span class="button__label">ok</span>
            </button>
        </fieldset>
    </form>
</div>

      
      
  
                  </div>
            </div>
        </div>

        <div id="hook"></div>

    <div class="site__content">
      <div class="container container--content">
        <div class="columns">
          <div class="column column--main">                                                                                                                   		     	

	<div class="portfolio">
	<div class="pagetitle"><h1>SIDN Labs Portfolio Checker</h1></div>
	<p>Versie 20130417</p>
	<br />
	</div>

	<div class="portfolio">

Als je een flink aantal domeinnamen hebt en je wilt deze beveiligen met <a href="http://www.dnssec.nl">DNSSEC</a>,
dan bestaat altijd het gevaar dat je een paar details over het hoofd ziet en
niet alle domeinen correct gesigned zijn. SIDN Labs heeft daarom de <a href="form">DNSSEC
Portfolio Checker</a> ontwikkeld, waarmee je dit op een snelle en eenvoudige manier
kunt controleren.

	<div class="pagetitle"><h2>Selecteer een <em>CSV</em> bestand met domeinnamen</h2></div>
	
	<form action="upload" method="POST" enctype="multipart/form-data">
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
	Er wordt per domeinnaam een DNSSEC-validatie via <a href="http://www.unbound.net">Unbound</a> uitgevoerd.
	De DNS-query vraagt om 'NS'-records. Er zal een <em>willekeurige</em> selectie van nameservers
	plaatsvinden. Er is geen garantie dat al je slave nameservers worden gecheckt. Als er geen NS-records
	zijn, levert dit een 'nodata'-antwoord op.
	</dd>

	<dt>Hoe ziet de uitvoer eruit?</dt>
	<dd>De uitvoer van deze check is:
	<p>
	<code>
		domeinnaam, DNS error, security status, uitgebreide error indien bogus
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
	bedoeld om hierover opheldering te verschaffen.
	<p/>
	De DNS-error is <b>nodata</b> als Unbound de gevraagde informatie (bijvoorbeeld NS records) niet kan vinden in het DNS.
	<p/>
	De uitvoer is gesorteerd op de security status, dus alle <em>b</em>ogus domeinen komen vooraan te staan.

	</dd>

	<dt>Kan er ook een enkele domein naam worden gecontroleerd?</dt>
	<dd>Uiteraard is dat mogelijk door een bestand te uploaden dat maar &eacute;&eacute;n domein naam bevat. Of je kunt
	de volgende URL gebruiken die een RESTful-achtige interface aanbiedt:
	<p>
	http://portfolio.sidnlabs.nl:8080/check/www.domeinnaam.nl
	</p>
	Bijvoorbeeld: 
	<a href="check/example.nl">portfolio.sidnlabs.nl:8080/check/www.example.nl</a>
	<p>
	LET OP: hier wordt om 'A'-records gevraagd. De uitvoer is gelijk aan de Portfolio-Checker uitvoer (CSV).
	</p>
	<p>
	Optioneel kan aan de RESTful interface ook een DNS recordtype worden meegeven, zodat er om iets anders gevraagd wordt
	dan een A record. Die interface werkt als volgt:
	<p>
	http://portfolio.sidnlabs.nl:8080/check/domeinnaam.nl/RRtype
	</p>
	Bijvoorbeeld: 
	<a href="check/example.nl/SOA">portfolio.sidnlabs.nl:8080/check/example.nl/TXT</a>
	<p>
	De lijst van DNS types die gebruikt kunnen worden is: SOA, A, NS, MX, TXT, AAAA, SRV, DS en DNSKEY .
	De uitvoer daarvan is gelijk aan de Portfolio-Checker uitvoer (CSV),
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
	De uitvoer kan op enig moment veranderen. Dus het advies is om voor belangrijk eigen gebruik, zelf de code
	te compileren en deze tool op een eigen systeem te draaien. Eenvoudige installatie-instructies staan op
	<a href="http://github.com/SIDN/unboundcheck">GitHub</a>.

	Neem bij problemen met het gebruik van deze software contact op met SIDN Labs via: <a href="http://www.sidnlabs.nl/over-sidn-labs/contact/">onze contactpagina</a>.
	</p>
	<p>
	SIDN kan de Portfolio Checker zelf gebruiken voor statistische doeleinden (% errors in de .nl-zone, etc.), maar zal geen data
	publiceren over registrars.
	</p>
	<p>&nbsp;</p>
	</div>

<!-- content ends here -->

</div>
</div>
</div>
</div>


</body>

</html>
`)
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
