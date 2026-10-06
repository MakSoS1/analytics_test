// Ordinary client-initiated telemetry, not a C2 agent. Fixed private lab endpoint.
package main

import (
 "bufio"
 "crypto/sha256"
 "crypto/tls"
 "crypto/x509"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "net"
 "os"
 "path/filepath"
 "time"
)

type Sample struct { Delay int `json:"delay"`; Data string `json:"data"` }

func tlsConfig(root string, server bool) *tls.Config {
 ca,err:=os.ReadFile(filepath.Join(root,"ca.pem"));if err!=nil {panic(err)}
 pool:=x509.NewCertPool();if !pool.AppendCertsFromPEM(ca){panic("CA")}
 name:="client";if server{name="server"}
 cert,err:=tls.LoadX509KeyPair(filepath.Join(root,name+".pem"),filepath.Join(root,name+".key"));if err!=nil{panic(err)}
 config:=&tls.Config{Certificates:[]tls.Certificate{cert},RootCAs:pool,ClientCAs:pool,MinVersion:tls.VersionTLS12}
 if server{config.ClientAuth=tls.RequireAndVerifyClientCert}else{config.ServerName="10.30.0.20"}
 return config
}

func main(){
 mode,useTLS,root:=os.Args[1],os.Args[2]=="true",os.Args[3]
 address:="10.30.0.20:8443"
 if mode=="server"{
  var listener net.Listener;var err error
  if useTLS{listener,err=tls.Listen("tcp",address,tlsConfig(root,true))}else{listener,err=net.Listen("tcp",address)}
  if err!=nil{panic(err)};defer listener.Close()
  conn,err:=listener.Accept();if err!=nil{panic(err)};defer conn.Close()
  scanner:=bufio.NewScanner(conn)
  for scanner.Scan(){sum:=sha256.Sum256(scanner.Bytes());if _,err=fmt.Fprintln(conn,hex.EncodeToString(sum[:]));err!=nil{panic(err)}}
  if err=scanner.Err();err!=nil{panic(err)}
 }else{
  raw,err:=os.ReadFile(os.Args[4]);if err!=nil{panic(err)}
  var schedule []Sample;if err=json.Unmarshal(raw,&schedule);err!=nil{panic(err)}
  var conn net.Conn
  if useTLS{conn,err=tls.DialWithDialer(&net.Dialer{Timeout:10*time.Second},"tcp",address,tlsConfig(root,false))}else{conn,err=net.DialTimeout("tcp",address,10*time.Second)}
  if err!=nil{panic(err)};defer conn.Close();scanner:=bufio.NewScanner(conn)
  for _,sample:=range schedule{
   time.Sleep(time.Duration(sample.Delay)*time.Second)
   sent:=float64(time.Now().UnixNano())/1e9
   if _,err=fmt.Fprintln(conn,sample.Data);err!=nil{panic(err)}
   sum:=sha256.Sum256([]byte(sample.Data))
   if !scanner.Scan() || scanner.Text()!=hex.EncodeToString(sum[:]){panic("telemetry acknowledgement mismatch")}
   encoded,_:=json.Marshal(map[string]interface{}{"at":sent,"ack_at":float64(time.Now().UnixNano())/1e9,"sha256":hex.EncodeToString(sum[:]),"verified":true})
   fmt.Println(string(encoded))
  }
 }
}
