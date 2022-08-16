package main

import (
	"flag"
	"fmt"
	"log"

	"./client"
	"./mycrypto"
	"./pubpro"
	"./server"
)

var version string = "v1.1.0 Stable"

func main() {
	fmt.Println("FullConeProxy \nAn Private Proxy Tool \nversion:", version)
	runningmode := flag.Bool("c", false, "add to run in client mode,default is server mode")
	socks5listen := flag.String("l", "[::]:10805", " only for client mode, set socks5 server listen address and port , default is [::]:10805")
	remoteaddr := flag.String("r", "127.0.0.1:10010", "only usr for client mode, set remote server address and port ,default is 127.0.0.1:10010")
	locallisten := flag.String("s", "127.0.0.1:10010", "only use for server mode,set server local listen address and port, default is 127.0.0.1:10010")
	stringkey := flag.String("w", "TESTMEBABY", "AES-256-GCM Mode Key ,input any string,default is TESTMEBABY")
	tcptimeout := flag.Int("tcptimeout", 600, "SET TCP Timeout,should not lower tha UDP Timeout")
	udptimeout := flag.Int("udptimeout", 600, "SET UDP timeout,should larger than TCO Timeout")
	ondebug := flag.Bool("debug", false, "ON DEBUG MODE")
	ontest := flag.Bool("test", false, "ON TEST MODE, WILL RUN SERVER AND CLIENT ON ONE MACHINE")
	complexaes := flag.Bool("lower", false, "Use lower security encryption methods(AES-128-GCM) instead of AES-256-GCM")
	showhelp := flag.Bool("h", false, "SHOW HELP")
	flag.Parse()
	if *showhelp {
		flag.Usage()
		return
	}
	mycrypto.SetDebug(*ondebug)
	client.SetDebug(*ondebug)
	server.SetDebug(*ondebug)
	pubpro.SetDebug(*ondebug)
	client.SetTCPTimeout(*tcptimeout)
	client.SetUDPTimeout(*udptimeout)
	server.SetTCPTimeout(*tcptimeout)
	server.SetUDPTimeout(*udptimeout)
	var key []byte
	var err error
	if !*complexaes {
		key, err = mycrypto.Strtokey128(*stringkey) //生成密钥
		if err != nil {
			log.Println("AES-128-GCM 密钥转化错误!,请检查: , ", err.Error())
			return
		}
	} else {
		key, err = mycrypto.Strtokey256(*stringkey) //生成密钥
		if err != nil {
			log.Println("AES-256-GCM密钥转化错误!,请检查: , ", err.Error())
			return
		}
	}
	if *ondebug {
		fmt.Printf("密钥密文为: %x\n", key)
	}
	if *ontest {
		go client.Client(*socks5listen, *remoteaddr, key)
	}

	if *runningmode {
		client.Client(*socks5listen, *remoteaddr, key)
	} else {
		server.Server(*locallisten, key)
	}

}
