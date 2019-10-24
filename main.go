package main

import (
	"os"
	"net/http"
	"log"
	"io/ioutil"
	"fmt"
	"time"
)


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


func getAPIKey() (string) {
	return os.Getenv("SHODAN_API_KEY")
}

func main() {
	ip := os.Args[1]
	json_data := QueryShodan(ip)
	fmt.Println(json_data)

}
