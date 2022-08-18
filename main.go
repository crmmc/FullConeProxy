package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"

	"./client"
	"./mycrypto"
	"./server"
)

var version string = "v1.2.4 stable"

func main() {
	fmt.Println("FullConeProxy \nAn Private Proxy Tool \nversion:", version)
	runningmode := flag.Bool("c", false, "add to run in client mode,default is server mode")
	socks5listen := flag.String("l", "[::]:10805", " only for client mode, set socks5 server listen address and port , default is [::]:10805")
	remoteaddr := flag.String("r", "127.0.0.1:10010", "only usr for client mode, set remote server address and port ,default is 127.0.0.1:10010, Multiple servers can be used at the same time. Each server address is separated by commas. The order of server access password must correspond to the server address. The password string is also separated by commas")
	locallisten := flag.String("s", "127.0.0.1:10010", "only use for server mode,set server local listen address and port, default is 127.0.0.1:10010")
	stringkey := flag.String("k", "TESTMEBABY", "AES-256-GCM Mode Key ,input any string,default is TESTMEBABY,The server password sequence must correspond to the server address sequence, and the passwords are separated by commas,In server mode, only the first password will be used")
	tcptimeout := flag.Int("tcptimeout", 30, "SET TCP Timeout,should not lower tha UDP Timeout")
	udptimeout := flag.Int("udptimeout", 150, "SET UDP timeout,should larger than TCO Timeout")
	ondebug := flag.Bool("debug", false, "ON DEBUG MODE")
	ontest := flag.Bool("test", false, "ON TEST MODE, WILL RUN SERVER AND CLIENT ON ONE MACHINE")
	serverchoicemode := flag.Bool("norandom", false, "In default ,When uding more than one server,use random method to choice server for each connection. Otherwise, only when the front server fails, the back server will be used as a backup")
	loweraes := flag.Bool("lower", false, "Use lower security encryption methods(AES-128-GCM) instead of AES-256-GCM , This option will affect the encryption of all passwords. When using multiple servers, please note that the password encryption mode used by each server cannot be customized")
	isongzip := flag.Bool("gzip", false, "On Gzip data compress method for cost less")
	showhelp := flag.Bool("h", false, "SHOW HELP")
	flag.Parse()
	if *showhelp {
		flag.Usage()
		return
	}
	if *ondebug {
		f, err := os.Create("debug.prof")
		if err != nil {
			log.Fatal("could not create memory profile: ", err)
		}
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
		f.Close()
	}
	mycrypto.SetDebug(*ondebug)
	mycrypto.SetGzip(*isongzip)
	var err error
	var sconfig []client.ServerConfig

	if *runningmode || *ontest {
		serveraddrstrings := strings.Split(*remoteaddr, ",")
		if len(serveraddrstrings) < 1 {
			log.Println("未找到足够的服务器地址! ", *remoteaddr)
			return
		}
		var serverkeys [][]byte
		serverkeys, err = getkeybyte(*stringkey, *loweraes)
		if err != nil {
			return
		}
		if len(serverkeys) < len(serveraddrstrings) {
			log.Println("未找到足够的服务器密码! ", *stringkey)
			return
		}
		for n, cstr := range serveraddrstrings {
			a, err := net.ResolveTCPAddr("tcp", cstr)
			if err == nil {
				//将配置文件添加进数组
				sconfig = append(sconfig, client.ServerConfig{ServerAddr: *a, ServerKey: serverkeys[n]})
			}
		}
		var ac client.AClient
		ac.Init()
		ac.SetDebug(*ondebug)
		ac.SetTCPReadTimeout(*tcptimeout)
		ac.SetUDPLifeTime(*udptimeout)
		ac.ServerChoiceRandom = !*serverchoicemode
		if *ontest {
			go ac.StartSocks5(*socks5listen, sconfig)
		} else {
			ac.StartSocks5(*socks5listen, sconfig)
			return
		}
	}
	var as server.AServer
	as.Init()
	as.SetDebug(*ondebug)
	as.SetTCPReadTimeout(*tcptimeout)
	as.SetUDPLifeTime(*udptimeout)
	astmp1, err := getkeybyte(*stringkey, *loweraes)
	if err != nil {
		return
	}
	as.StartServer(*locallisten, astmp1[0])
	as.StartLoop()
}

func getkeybyte(keys string, loweraes bool) ([][]byte, error) {
	serverkeys := strings.Split(keys, ",")
	returnkeys := make([][]byte, len(serverkeys))
	var err error
	var tmpkey []byte
	for n, gkt := range serverkeys {
		if loweraes {
			tmpkey, err = mycrypto.Strtokey128(gkt) //生成密钥
			if err != nil {
				log.Println("无法生成AES-128-GCM秘钥！ ", err.Error())
				return returnkeys, err
			}
			returnkeys[n] = tmpkey
		} else {
			tmpkey, err = mycrypto.Strtokey256(gkt) //生成密钥
			if err != nil {
				log.Println("无法生成AES-256-GCM秘钥！ ", err.Error())
				return returnkeys, err
			}
			returnkeys[n] = tmpkey
		}
	}
	return returnkeys, nil
}
