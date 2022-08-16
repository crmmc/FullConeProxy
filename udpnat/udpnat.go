package udpnat

import (
	"fmt"
	"log"
	"net"
	"time"

	"../pubpro"
)

var isdebug bool = true

func UdpNat(udpconn *net.UDPConn) bool {
	defer udpconn.Close()

	for {
		var err error
		var n int
		var n1err error
		var addr1 net.Addr
		lbuf := make([]byte, 1024*2)
		n, addr1, n1err = udpconn.ReadFromUDP(lbuf)
		if n1err != nil {
			fmt.Println("读数据出错,UDP NAT退出！", n1err.Error())
			return false
		}
		fmt.Printf("UDP NAT收到数据： |%x| FROM: %s\n", lbuf[:n], addr1.String())
		var targetaddr *net.UDPAddr = new(net.UDPAddr)
		var fromlocaldata []byte = lbuf[3:n]
		var realdata []byte
		switch fromlocaldata[0] {
		case 0x01:
			//IPV4
			targetaddr.IP = fromlocaldata[1:5]
			targetaddr.Port = pubpro.BytesTouInt16(fromlocaldata[5:7])
			realdata = fromlocaldata[7:]
		case 0x04:
			//IPV6
			targetaddr.IP = fromlocaldata[1:17]
			targetaddr.Port = pubpro.BytesTouInt16(fromlocaldata[17:19])
			realdata = fromlocaldata[19:]
		case 0x03:
			//Domain
			realdata = fromlocaldata[2+int(fromlocaldata[1])+2:]
			targetaddr, n1err = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", (fromlocaldata[2:2+int(fromlocaldata[1])]), pubpro.BytesTouInt16(fromlocaldata[2+int(fromlocaldata[1]):2+int(fromlocaldata[1])+2])))
			if n1err != nil {
				if isdebug {
					log.Println("SERVER 处理UDP数据时发生错误: 解析目标网址失败! , ", n1err.Error())
				}
			}
		default:
			if isdebug {
				log.Println("SERVER 处理UDP数据时发生错误: 地址类型无法识别! , ", n1err.Error())
			}
		}
		if n1err != nil {
			if isdebug {
				log.Printf("此UoT包因错误而被忽略 |%x| ,%s \n", fromlocaldata[:n], n1err.Error())
			}
			continue //跳过这个包
		}
		toconn, toerr := net.ListenUDP("udp", nil)
		if toerr != nil {
			fmt.Println("申请新的UDP端口出现问题!", toerr.Error())
			return false
		}
		_, toerr = toconn.WriteToUDP(realdata, targetaddr)
		if toerr != nil {
			fmt.Println("发送数据出错!", err.Error())
			return false
		}
		toconn.SetDeadline(time.Now().Add(time.Duration(300) * time.Second))
		newbuf := make([]byte, 1024*4)
		var faraddr *net.UDPAddr
		go func() {
			for {
				n, faraddr, n1err = toconn.ReadFromUDP(newbuf)
				if n1err != nil {
					fmt.Println("UDP NAT 无法继续读取数据了！", n1err.Error())
					return
				}
				var writebytes []byte = []byte{}
				fmt.Printf("收到回复: %x  \n", newbuf[:n])
				writebytes = pubpro.AddrToBytes(faraddr.IP, faraddr.Port)
				writebytes = pubpro.ConnectBytes([]byte{0x00, 0x00, 0x00}, writebytes)
				writebytes = pubpro.ConnectBytes(writebytes, newbuf[:n])
				udpconn.WriteToUDP(writebytes, addr1.(*net.UDPAddr))
			}
		}()
	}
}
