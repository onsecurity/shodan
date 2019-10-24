package main

import (
	"os"
	"net/http"
	"log"
	"io/ioutil"
	"github.com/tidwall/gjson"
	"encoding/json"
	"fmt"
	"sync"
	"net"
	"time"
)

type Host struct {
	IP string `json:"i`
	Hostnames []string `json:"hostnames"`
	Ports []int64 `json:"ports"`
	Vulns []CVE `json:"vulns"`
}


type CVE struct {
	name string
	cvss_vector string
	cvss_score float32
}

func QueryShodan(ip string) string {
	api_key := getAPIKey()
	key_fragment := "?key=" + api_key

	resp, err := http.Get("https://api.shodan.io/shodan/host/" + ip + key_fragment)

	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode != 200 {
		time.Sleep(1)
		return QueryShodan(ip)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Fatal(err)
	}

	string_body := string(body)
	return string_body
}

func createHost(json string) Host {
	ip := gjson.Get(json, "ip_str")

	ports := gjson.Get(json, "ports")

	hostnames := gjson.Get(json, "hostnames")



	var port_list []int64
	var hostname_list []string

	for _, port := range ports.Array() {
		port_list = append(port_list, port.Int())
	}

	for _, hostname := range hostnames.Array() {
		hostname_list = append(hostname_list, hostname.String())
	}

	host := Host{
		IP: ip.String(),
		Hostnames: hostname_list,
		Ports: port_list,
	}

	return host
}

func resolveDNS (domain string) []net.IP {
	ips, err := net.LookupIP(domain)
	if err != nil {
		log.Fatal(err)
	}

	return ips
}
func parseArgs() []string {
	domains := os.Args[1:]
	return domains
}

func getAPIKey() string {
	return os.Getenv("SHODAN_API_KEY")
}

func main() {
	domains := parseArgs()

	var wg_dns sync.WaitGroup
	var wg_shodan sync.WaitGroup

	ip_channel := make(chan string)

	for _, domain := range domains {
		wg_dns.Add(1)
		go func(domain string, c chan string) {
			defer wg_dns.Done()
			ips := resolveDNS(domain)
			for _, ip := range ips {
				c <- ip.String()
			}
		}(domain, ip_channel)
	}

	go func() {
		wg_dns.Wait()
		close(ip_channel)
	} ()

	for ip := range ip_channel {
		wg_shodan.Add(1)
		go func(ip string) {
			defer wg_shodan.Done()
			json_data := QueryShodan(ip)
			host := createHost(json_data)
			host_data, _ := json.Marshal(host)
			fmt.Println(string(host_data))
		}(ip)
	}
	wg_shodan.Wait()
}
