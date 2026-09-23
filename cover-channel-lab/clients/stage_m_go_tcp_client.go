package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

func send(c net.Conn, f string, b []byte) error {
	switch f {
	case "fixed":
		var h [2]byte
		binary.BigEndian.PutUint16(h[:], uint16(len(b)))
		_, e := c.Write(append(h[:], b...))
		return e
	case "length_prefixed":
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], uint32(len(b)))
		_, e := c.Write(append(h[:], b...))
		return e
	default:
		_, e := c.Write(append(b, '\n'))
		return e
	}
}
func recv(c net.Conn, r *bufio.Reader, f string) ([]byte, error) {
	if f == "line" {
		return r.ReadBytes('\n')
	}
	nbytes := 2
	if f == "length_prefixed" {
		nbytes = 4
	}
	h := make([]byte, nbytes)
	if _, e := io.ReadFull(r, h); e != nil {
		return nil, e
	}
	n := int(binary.BigEndian.Uint16(h))
	if nbytes == 4 {
		n = int(binary.BigEndian.Uint32(h))
	}
	b := make([]byte, n)
	_, e := io.ReadFull(r, b)
	return b, e
}
func main() {
	if len(os.Args) != 8 {
		os.Exit(2)
	}
	host := os.Args[1]
	port, _ := strconv.Atoi(os.Args[2])
	f := os.Args[3]
	count, _ := strconv.Atoi(os.Args[4])
	req, _ := strconv.Atoi(os.Args[5])
	resp, _ := strconv.Atoi(os.Args[6])
	delay, _ := strconv.Atoi(os.Args[7])
	c, e := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if e != nil {
		panic(e)
	}
	defer c.Close()
	r := bufio.NewReader(c)
	fmt.Fprintf(c, "STAGEM1 %s %d\n", f, resp)
	ack, _ := r.ReadString('\n')
	if ack != "OK\n" {
		panic("bad ack")
	}
	lens := []int{}
	for i := 0; i < count; i++ {
		b := make([]byte, req)
		for j := range b {
			b[j] = byte((i + j) % 251)
		}
		if e := send(c, f, b); e != nil {
			panic(e)
		}
		x, e := recv(c, r, f)
		if e != nil {
			panic(e)
		}
		lens = append(lens, len(x))
		if delay > 0 && i+1 < count {
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"reply_lengths": lens})
}
