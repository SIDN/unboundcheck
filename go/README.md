**Please be advised of the following: the root KSK is hardcoded in the sourcecode. And this moment ICANN is in the process of changing the KSK of the root. Currently the old and the new KSK are present in this sourcecode. We will remove the old KSK from this sourcecode when applicable. Please make sure you are not using the old KSK or this tool will stop working. See: https://www.icann.org/resources/pages/ksk-rollover .** 

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

http://portfolio.sidnlabs.nl/form

https://portfolio.sidnlabs.nl/check/example.nl

https://portfolio.sidnlabs.nl/check/example.nl/TXT

Known (other) users:

http://www.phishingscorecard.com/

