package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

func main() {
	listenPort := flag.String("port", "8080", "Port for the web server")
	targetURL := flag.String("url", "", "Target URL for the HTTP request")
	proxyURL := flag.String("proxy", "", "Proxy server URL")
	flag.Parse()

	if *targetURL == "" || *proxyURL == "" {
		log.Fatal("Please provide both the target URL and the proxy URL")
	}

	_, err := url.ParseRequestURI(*targetURL)
	if err != nil {
		log.Fatal("Provided invalid target URL, it should include a schema (http:// or https://)")
	}

	_, err = url.ParseRequestURI(*proxyURL)
	if err != nil {
		log.Fatal("Provided invalid proxy URL, it should include a schema (http:// or https://)")
	}

	proxy, err := url.Parse(*proxyURL)

	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxy),
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		resp, err := client.Get(*targetURL)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Error while making the request: ", err)
		} else {
			defer resp.Body.Close()
			w.WriteHeader(resp.StatusCode)
			body, _ := ioutil.ReadAll(resp.Body)
			fmt.Fprint(w, string(body))
		}
	})

	log.Fatal(http.ListenAndServe(":"+*listenPort, nil))
}

