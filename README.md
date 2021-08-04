# goarl

goarl is a tool that can quickly detect an Akamai misconfiguration which may mean arbitrary content hosted on other Akamai sites can be loaded on the domain in question. The tool was made after reading this [blog](https://warandcode.com/post/akamai-arl-hack/) which demonstrates the attack vector, essentially:

*"We are looking for abandoned subdomains that give us a “naked” look at Akamai. This makes them susceptible to loading whatever content from other Akamai sites that we want."*

Being able to render arbitrary content on a domain could lead to XSS and / or ATO, or possibly worse.

## Installation

Ensure you have [go](https://golang.org/doc/install) installed with your [$GOPATH](https://golang.org/doc/gopath_code) set correctly. 

```bash
go get -u github.com/cybercdh/goarl
```

## Usage

```text
$ cat urls.txt | goarl

options:

 -c int = concurrency (default 20; 50 is quick)
 -v = verbose (for added info)
 -t = timeout (milliseconds, if you want to adjust the timeout for HTTP GET request attempts)
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)