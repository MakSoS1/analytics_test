package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

type Req struct {
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	CampaignID string   `json:"campaign_id"`
	Framing    string   `json:"framing"`
	Direction  string   `json:"direction"`
	Payloads   []string `json:"payloads"`
	DelayMS    int      `json:"delay_ms"`
}

func writeFrame(w io.Writer, framing string, data []byte) error {
	switch framing {
	case "len16":
		h := make([]byte, 2)
		binary.BigEndian.PutUint16(h, uint16(len(data)))
		if _, e := w.Write(h); e != nil {
			return e
		}
		_, e := w.Write(data)
		return e
	case "len32":
		h := make([]byte, 4)
		binary.BigEndian.PutUint32(h, uint32(len(data)))
		if _, e := w.Write(h); e != nil {
			return e
		}
		_, e := w.Write(data)
		return e
	case "newline":
		_, e := fmt.Fprintf(w, "%s\n", strings.ReplaceAll(string(data), "\n", "."))
		return e
	default:
		b := make([]byte, 64)
		for i := range b {
			b[i] = '.'
		}
		copy(b, data)
		_, e := w.Write(b)
		return e
	}
}
func main() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}
	var q Req
	if err = json.Unmarshal(raw, &q); err != nil {
		panic(err)
	}
	c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", q.Host, q.Port), 5*time.Second)
	if err != nil {
		panic(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	fmt.Fprintf(c, "{\"campaign_id\":%q,\"framing\":%q,\"direction\":%q}\n", q.CampaignID, q.Framing, q.Direction)
	br := bufio.NewReader(c)
	if _, err = br.ReadString('\n'); err != nil {
		panic(err)
	}
	for _, p := range q.Payloads {
		if err = writeFrame(c, q.Framing, []byte(p)); err != nil {
			panic(err)
		}
		if q.DelayMS > 0 {
			time.Sleep(time.Duration(q.DelayMS) * time.Millisecond)
		}
	}
	c.SetDeadline(time.Now().Add(500 * time.Millisecond))
	io.Copy(io.Discard, br)
	fmt.Println("ok")
}
