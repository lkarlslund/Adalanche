package collect

import (
	"fmt"
	"net/http"
	"time"
)

func TestInternet() string {
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("http://www.msftncsi.com/ncsi.txt")
	if err != nil {
		return err.Error()
	} else if resp.StatusCode == 200 {
		return "Connected"
	} else {
		return fmt.Sprintf("Status code %v", resp.StatusCode)
	}
}
