package main
import (
  "bytes"
  "crypto/tls"
  "encoding/base64"
  "encoding/json"
  "fmt"
  "io"
  "net/http"
  "os"
  "time"
)
type Req struct { URL string `json:"url"`; Method string `json:"method"`; Headers map[string]string `json:"headers"`; BodyB64 string `json:"body_b64"` }
func main(){
  raw,err:=io.ReadAll(os.Stdin); if err!=nil{panic(err)}
  var q Req; if err=json.Unmarshal(raw,&q); err!=nil{panic(err)}
  body,_:=base64.StdEncoding.DecodeString(q.BodyB64)
  tr:=&http.Transport{TLSClientConfig:&tls.Config{InsecureSkipVerify:true},ForceAttemptHTTP2:true}
  c:=&http.Client{Transport:tr,Timeout:10*time.Second,CheckRedirect:func(req *http.Request, via []*http.Request) error{return http.ErrUseLastResponse}}
  req,err:=http.NewRequest(q.Method,q.URL,bytes.NewReader(body)); if err!=nil{panic(err)}
  for k,v:=range q.Headers{req.Header.Set(k,v)}
  resp,err:=c.Do(req); if err!=nil{fmt.Fprintln(os.Stderr,err); os.Exit(2)}
  io.Copy(io.Discard,resp.Body); resp.Body.Close(); fmt.Printf("%d\n",resp.StatusCode)
}
