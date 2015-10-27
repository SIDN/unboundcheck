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
    <title>SIDN Labs: DNSSEC portfolio checker</title>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
    <!-- Twitter Card -->
    <meta name="twitter:card" content="summary" />
    <meta name="twitter:description" content="Lees meer op sidn.nl" />
    <meta name="twitter:image" content="https://www.sidn.nl/assets/img/og-image.jpg" />
    <meta name="twitter:site" content="@sidn" />
    <meta name="twitter:title" content="SIDN : Homepage" />
    <meta name="twitter:url" content="https://www.sidn.nl/sidn-labs/" />
    <meta name="keywords" content="" />
    <script>
    (function(i, s, o, g, r, a, m) {
        i['GoogleAnalyticsObject'] = r;
        i[r] = i[r] || function() {
            (i[r].q = i[r].q || []).push(arguments)
        }, i[r].l = 1 * new Date();
        a = s.createElement(o),
            m = s.getElementsByTagName(o)[0];
        a.async = 1;
        a.src = g;
        m.parentNode.insertBefore(a, m)
    })(window, document, 'script', '//www.google-analytics.com/analytics.js', 'ga');

    ga('create', 'UA-52545763-6', 'auto');
    ga('send', 'pageview');
    </script>
    <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
    <link type="text/css" rel="stylesheet" href="//fast.fonts.net/cssapi/f726c309-8879-4771-b2c6-33d945a9911b.css" />
    <link type="text/css" rel="stylesheet" href="//workbench.sidnlabs.nl/assets/css/layout.css" />
    <link rel="icon" type="image/png" href="//workbench.sidnlabs.nl/assets/img/favicon.png" />
    <link rel="apple-touch-icon" href="//workbench.sidnlabs.nl/assets/img/apple-touch-icon.png" />
    <link rel="apple-touch-icon" sizes="76x76" href="//workbench.sidnlabs.nl/assets/img/apple-touch-icon-76x76.png" />
    <link rel="apple-touch-icon" sizes="120x120" href="//workbench.sidnlabs.nl/assets/img/apple-touch-icon-120x120.png" />
    <link rel="apple-touch-icon" sizes="152x152" href="//workbench.sidnlabs.nl/assets/img/apple-touch-icon-152x152.png" />
    <script type="text/javascript" src="//workbench.sidnlabs.nl/assets/js/head.js"></script>
    <script type="text/javascript" src="//workbench.sidnlabs.nl/assets/js/galleria/galleria-1.4.2.min.js"></script>
</head>

<body class="labs">
    <div id="og-linkedin"><img src="//workbench.sidnlabs.nl/assets/img/og-image-linkedin.png" alt="" title="" /></div>
    <div class="navigation" id="nav">
        <div class="navigation-container">
            <div class="c">
                <nav role="navigation">
                    <div class="logo">
                        <a href="https://www.sidn.nl/"><img src="//workbench.sidnlabs.nl/assets/img/logo-sidn-body.svg" alt="SIDN logo" title="" /></a>
                    </div>
                    <div class="markers">
                        <a class="icon-nl-domain" id="marker-domain" href="https://www.sidn.nl/whois"></a>
                        <a class="icon-search" id="marker-search" href="https://www.sidn.nl/zoeken/"><span>Zoeken</span></a>
                        <a class="icon-list" id="marker-nav"></a>
                    </div>
                    <div class="navigation-lists" id="nav-lists">
                        <div class="navigation-main">
                            <ul>
                                <li>
                                    <a href="https://www.sidn.nl/t/nl-domeinnaam">.nl-domeinnaam</a>
                                </li>
                                <li>
                                    <a href="https://www.sidn.nl/t/diensten">Diensten</a>
                                </li>
                                <li>
                                    <a href="https://www.sidn.nl/t/veilig-internet">Veilig internet</a>
                                </li>
                                <li>
                                    <a href="https://www.sidn.nl/t/kennis-en-ontwikkeling">Kennis en ontwikkeling</a>
                                </li>
                                <li class="active">
                                    <a href="https://www.sidn.nl/sidn-labs/">SIDN Labs</a>
                                </li>
                                <li>
                                    <a href="https://www.sidn.nl/t/over-sidn">Over SIDN</a>
                                </li>
                            </ul>
                        </div>
                        <div class="navigation-related">
                            <ul>
                                <li><a href="https://www.sidn.nl/faq/">Veelgestelde vragen</a></li>
                                <li><a href="https://registrars-dev.cloud.usmedia.nl?language_id=1">Login registrars</a></li>
                                <li class="language-switch">
                                    <span>NL</span> / <a href="https://www.sidn.nl/sidn-labs/index?language_id=2">EN</a>
                                </li>
                            </ul>
                        </div>
                    </div>
                </nav>
            </div>
        </div>
        <div class="search" id="site-search">
            <div class="c">
                <form action="/search" method="get" class="search-form" id="site-search-form">
                    <fieldset>
                        <legend>Zoek in sidn.nl</legend>
                        <div class="search-wrapper">
                            <i class="icon-search"></i>
                            <input type="search" placeholder="Zoek in sidn.nl" name="q" id="site-search-input" value="" />
                            <button type="submit">
                                <span>Zoek</span>
                            </button>
                        </div>
                    </fieldset>
                </form>
            </div>
        </div>
        <div class="domain-search" id="domain-search">
            <div class="domain-search-container">
                <div class="c">
                    <form method="get" action="./whois" class="domain-search-form" id="domain-search-form">
                        <fieldset>
                            <legend>whois.label.legend</legend>
                            <div class="search-wrapper">
                                <i class="icon-nl-domain"></i>
                                <input id="domain-search-input" autocomplete="off" type="search" name="q" placeholder="Check hier uw .nl-domeinnaam" value="" /><!--
                             --><button type="submit">
                                    <span>ok</span>
                                </button>
                            </div>
                        </fieldset>
                    </form>
                </div>
            </div>
        </div>
    </div>
    <div id="domain-hook"></div>
    <div class="page-content content">
        <nav class="sub-navigation">
            <div class="container">
                <h1 class="sub-navigation__logo"><a href="https://www.sidn.nl/sidn-labs/"><img src="//workbench.sidnlabs.nl/assets/img/logo-sidn-labs.png" alt="SIDN Labs"></a></h1>
                <ul class="sub-navigation__list">
                    <li class="sub-navigation__item">
                        <a class="sub-navigation__link" href="https://www.sidn.nl/sidn-labs/software-en-tools">Software en tools</a>
                    </li>
                    <li class="sub-navigation__item">
                        <a class="sub-navigation__link" href="https://www.sidn.nl/sidn-labs/publicaties">Publicaties</a>
                    </li>
                    <li class="sub-navigation__item">
                        <a class="sub-navigation__link" href="https://stats.sidnlabs.nl">Statistieken</a>
                    </li>
                    <li class="sub-navigation__item">
                        <a class="sub-navigation__link" href="https://www.sidn.nl/sidn-labs/projecten">Projecten</a>
                    </li>
                    <li class="sub-navigation__item">
                        <a class="sub-navigation__link" href="https://www.sidn.nl/sidn-labs/over-labs">Over SIDN Labs</a>
                    </li>
                </ul>
                <ul class="client-info">
                    <li class="client-info__item"><a href="https://github.com/SIDN"><i class="icon icon-github4"></i></a></li>
                    <li class="client-info__item" id="sidn_ipv6_check"></li>
                    <li class="client-info__item" id="sidn_dnssec_check"></li>
                </ul>
            </div>
        </nav>
        <div class="dotcms-row">
            <div class="dotcms-column">
            <!-- content starts here -->

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
    <!-- /container-->
    <footer>
        <div class="page-footer">
            <div class="container">
                <nav>
                    <div class="sitemap">
                        <section>
                            <h1>
                            <a href="https://www.sidn.nl/t/nl-domeinnaam">.nl-domeinnaam</a>
                    </h1>
                            <ul>
                                <li><a href="https://www.sidn.nl/t/nl-domeinnaam#category-dcef45d7-3ea0-41a2-a6bb-25983546eaaf">Domeinnaam uitgelegd</a></li>
                                <li><a href="https://www.sidn.nl/t/nl-domeinnaam#category-33dd40e2-ff5d-4192-b7d0-5659616dc4e0">Domeinnaam zoeken</a></li>
                                <li><a href="https://www.sidn.nl/t/nl-domeinnaam#category-4f128bd5-7fc4-4eaa-9d36-fa101f30efe8">Domeinnaam registreren</a></li>
                                <li><a href="https://www.sidn.nl/t/nl-domeinnaam#category-0b6735e5-e92a-43e9-834d-ae3291172786">Domeinnaam aanpassen</a></li>
                                <li><a href="https://www.sidn.nl/t/nl-domeinnaam#category-5f8abfe9-3a81-4edf-a913-44b39f0ca76e">Registrar zoeken</a></li>
                                <li><a href="https://www.sidn.nl/t/nl-domeinnaam#category-b5f5efe6-7c3e-4b63-9a8e-b982bd829cf3">Registrar worden</a></li>
                                <li><a href="https://www.sidn.nl/t/nl-domeinnaam#category-6bad0d84-0b1b-41fd-948d-3f0ba9a1c86a">Klacht of geschil over domeinnaam</a></li>
                            </ul>
                        </section>
                        <section>
                            <h1>
                            <a href="https://www.sidn.nl/t/diensten">Diensten</a>
                    </h1>
                            <ul>
                                <li><a href="https://www.sidn.nl/t/diensten#category-8f9ae076-f148-4a1d-8848-81753eb336d0">Domeinnaam&shy;bewakingsservice</a></li>
                                <li><a href="https://www.sidn.nl/t/diensten#category-a05a6553-0a14-4806-8a31-f77d1d9c3a1e">Registrydiensten</a></li>
                                <li><a href="https://www.sidn.nl/t/diensten#category-6f29f1c8-4be5-4e78-9c3a-225c2efa01ba">Trust frameworkbeheer</a></li>
                            </ul>
                        </section>
                        <section>
                            <h1>
                            <a href="https://www.sidn.nl/t/veilig-internet">Veilig internet</a>
                    </h1>
                            <ul>
                                <li><a href="https://www.sidn.nl/t/veilig-internet#category-849c1352-ef4e-4fcd-b1b4-6e0b42f35969">Veilig .nl</a></li>
                                <li><a href="https://www.sidn.nl/t/veilig-internet#category-5ab6a7cf-ffcf-4a20-a6b4-71369702e46a">Internetmisbruik</a></li>
                                <li><a href="https://www.sidn.nl/t/veilig-internet#category-23219ca7-0be7-4115-806d-f19ca977f8fe">Beveiligingsmogelijkheden</a></li>
                            </ul>
                        </section>
                        <section>
                            <h1>
                            <a href="https://www.sidn.nl/t/kennis-en-ontwikkeling">Kennis en ontwikkeling</a>
                    </h1>
                            <ul>
                                <li><a href="https://www.sidn.nl/t/kennis-en-ontwikkeling#category-7192430e-1d43-4c96-8ab5-fb6c91d53282">SIDN Labs</a></li>
                                <li><a href="https://www.sidn.nl/t/kennis-en-ontwikkeling#category-5d16cbbe-d906-4cbb-871e-418adb2ae049">Publicaties en presentaties</a></li>
                                <li><a href="https://www.sidn.nl/t/kennis-en-ontwikkeling#category-e6148e5b-7412-49ae-a2d0-45dbdd9219cb">Marktonderzoek</a></li>
                                <li><a href="https://www.sidn.nl/t/kennis-en-ontwikkeling#category-0d906933-9114-4981-b3cc-7a8598d16e5f">Online cursussen</a></li>
                                <li><a href="https://www.sidn.nl/t/kennis-en-ontwikkeling#category-cc456281-3b70-4763-8aa1-eec933f8f472">Organisatie van het internet</a></li>
                                <li><a href="https://www.sidn.nl/begrippen">Begrippenlijst</a></li>
                            </ul>
                        </section>
                        <section>
                            <h1>
                            <a href="https://www.sidn.nl/sidn-labs/">SIDN Labs</a>
                    </h1>
                            <ul>
                                <li><a href="https://www.sidn.nl/sidn-labs/software-en-tools">Software en tools</a></li>
                                <li><a href="https://www.sidn.nl/sidn-labs/publicaties">Publicaties</a></li>
                                <li><a href="https://stats.sidnlabs.nl">Statistieken</a></li>
                                <li><a href="https://www.sidn.nl/sidn-labs/projecten">Projecten</a></li>
                                <li><a href="https://www.sidn.nl/sidn-labs/over-labs">Over SIDN Labs</a></li>
                            </ul>
                        </section>
                        <section>
                            <h1>
                            <a href="https://www.sidn.nl/t/over-sidn">Over SIDN</a>
                    </h1>
                            <ul>
                                <li><a href="https://www.sidn.nl/t/over-sidn#category-2986051c-04be-46f7-bfd0-5c801151d076">Wie wij zijn</a></li>
                                <li><a href="https://www.sidn.nl/a/over-sidn/contact">Contact</a></li>
                                <li><a href="https://www.sidn.nl/t/over-sidn#category-d6734dd9-78d4-4430-85f6-60ae65567ae2">Maatschappelijke betrokkenheid</a></li>
                                <li><a href="https://www.sidn.nl/t/over-sidn#category-e16b4bfb-f555-4114-8045-47b0209c87ea">Affiliate worden</a></li>
                                <li><a href="https://www.sidn.nl/werken-bij-sidn/">Werken bij SIDN</a></li>
                                <li><a href="https://www.sidn.nl/nieuws">Nieuwsberichten</a></li>
                                <li><a href="https://www.sidn.nl/faq">Veelgestelde vragen</a></li>
                            </ul>
                        </section>
                    </div>
                    <div class="footer-nav-container">
                        <div class="footer-nav">
                            <ul>
                                <li><a href="https://www.sidn.nl/rss/overview/">RSS</a></li>
                                <li><a href="https://sidn-dev.cloud.usmedia.nl/a/over-sidn/algemene-voorwaarden">Algemene voorwaarden</a></li>
                                <li><a href="https://sidn-dev.cloud.usmedia.nl/a/over-sidn/cookieverklaring">Cookieverklaring</a></li>
                                <li><a href="https://sidn-dev.cloud.usmedia.nl/a/over-sidn/privacy">Privacy</a></li>
                                <li><a href="https://sidn-dev.cloud.usmedia.nl/a/over-sidn/terms-of-website-use">Terms of use</a></li>
                                <li><a href="https://sidn-dev.cloud.usmedia.nl/a/over-sidn/contact">Contact</a></li>
                            </ul>
                        </div>
                        <div class="footer-payoff">
                            <h2>SIDN - Het bedrijf achter .nl</h2>
                        </div>
                    </div>
                </nav>
            </div>
        </div>
        <div class="footer-org">
            <div class="container" itemscope="" itemtype="http://schema.org/Organization">
                <meta itemprop="logo" content="//workbench.sidnlabs.nl/assets/img/og-image.png" />
                <meta itemprop="telephone" content="+31263525500" />
                <meta itemprop="name" content="Stichting Internet Domeinregistratie Nederland" />
                <meta itemprop="alternateName" content="SIDN" />
                <meta itemprop="url" content="http:/www.sidn.nl" />
                <meta itemprop="email" content="support@sidn.nl" />
                <h1><abbr title="Stichting Internet Domeinregistratie Nederland">SIDN</abbr></h1>
                <ul itemprop="address" itemscope="" itemtype="http://schema.org/PostalAddress">
                    <meta itemprop="addressCountry" content="Nederland" />
                    <li itemprop="streetAddress">Meander 501</li>
                    <li><span itemprop="postalCode">6825 MD</span> <span itemprop="addressLocality">Arnhem</span></li>
                    <li>Telefoon: <a href="tel:+31263525500">026 352 55 00</a></li>
                    <li>E-mail: <a href="mailto:support@sidn.nl">support@sidn.nl</a></li>
                </ul>
                <div class="social channels">
                    <ul>
                        <li><a href="https://twitter.com/SIDN" class="icon-twitter2"><span>Twitter</span></a></li>
                        <li><a href="http://www.youtube.com/user/SIDNArnhem" class="icon-youtube"><span>Youtube</span></a></li>
                        <li><a href="http://www.linkedin.com/company/sidn" class="icon-linkedin2"><span>LinkedIn</span></a></li>
                    </ul>
                </div>
            </div>
        </div>
    </footer>
    <script type="text/javascript" src="//workbench.sidnlabs.nl/assets/js/app.js"></script>
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
