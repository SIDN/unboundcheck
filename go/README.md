Quick install:

- sudo apt-get update
- sudo apt-get upgrade
- sudo apt-get install golang libunbound-dev
- sudo apt-get install git
- sudo apt-get install gcc
- sudo go get github.com/SIDN/unboundcheck/go
- sudo go build github.com/SIDN/unboundcheck/go
- sudo mkdir /home/unbouncheck
- sudo cp go /home/unboundcheck/gocheck
  (perhaps set some ownerships and 'strip' it)
- place script below in /etc/init named gocheck.conf
  (probably needs some adjustments first)
- sudo start gocheck
- Surf to http://yourserver:8080/form

Have fun!

Known users:

http://www.phishingscorecard.com/

