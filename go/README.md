**Please be advised of the following:** the root KSK-2017 is hardcoded in this sourcecode. The old KSK has been removed from this sourcecode on October 11th 2018. Also, it is planned that a new KSK (KSK-2024) is scheduled to become active October 11, 2026. We may, or may not update this source code by that time. You are advised to keep an eye on https://www.iana.org/dnssec/files regarding this rollover.

Quick install:

- sudo apt-get update
- sudo apt-get upgrade
- sudo apt-get install golang libunbound-dev
- sudo apt-get install git
- sudo apt-get install gcc
- sudo go get github.com/SIDN/unboundcheck/go
- sudo go build github.com/SIDN/unboundcheck/go
- sudo mkdir /home/unboundcheck
- sudo cp go /home/unboundcheck/gocheck
  (perhaps set some ownerships and 'strip' it)
- place portfolio.conf in /etc/init named as gocheck.conf
  (may need some adjustments first, to suite your exact needs)
- sudo start gocheck
- Surf to http://yourserver:8080/form

Have fun!

Working demo:

https://portfolio.sidnlabs.nl/form

https://portfolio.sidnlabs.nl/check/servfail.sidnlabs.nl

https://portfolio.sidnlabs.nl/check/example.nl/TXT

Known (other) users:

https://www.phishingscorecard.com/

