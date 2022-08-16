package server

import (
	"fmt"
	"log"
	"net"
	"time"

	"../mycrypto"
	"../pubpro"
)

var mybufsize int = 1024 * 8
var tcpreadtimeout int = 60  //TCP Read Timeout 不要小于UDP Timeout
var tcpwritetimeout int = 15 //TCP Write Timeout 一般不是太小就行
var udplivetime int = 600    //每个UDP通道保持的时间
var isdebug bool = false

func SetDebug(mode bool) {
	isdebug = mode
}

func SetTCPTimeout(st int) {
	tcpreadtimeout = st
}

func SetUDPTimeout(st int) {
	udplivetime = st
}

func Server(locallisten string, key []byte) {
	defer log.Panic("Server Exit....")
	fmt.Println("启动SERVER,监听地址为", locallisten)
	sl, err := net.Listen("tcp", locallisten)
	if err != nil {
		log.Println("SERVER监听错误，", locallisten, " , ", err.Error())
		return
	}
	defer sl.Close()
	for {
		sconn, err := sl.Accept()
		if err != nil {
			log.Println("SERVER 接受连接时出现错误! , ", err.Error())
			break
		}

		sconn.(*net.TCPConn).SetLinger(0)
		sconn.(*net.TCPConn).SetNoDelay(true)
		sconn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(tcpwritetimeout)))
		sconn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(tcpreadtimeout)))
		go process(sconn, key)
	}
	sl.Close()
}

//命令处理
func process(sconn net.Conn, key []byte) bool {
	defer sconn.Close()
	timeStamp := time.Now().Unix()
	timeLayout := "2006-01-02 15:04"
	timeStr := time.Unix(timeStamp, 0).Format(timeLayout)
	var adddata []byte
	var err error
	adddata, err = mycrypto.Strtokey128(timeStr)
	if err != nil {
		log.Println("SERVER 生成首包时间戳失败! ,", err.Error())
		return false
	}
	dedata, err := mycrypto.DecryptFrom(sconn, key, adddata)
	if err != nil {
		if isdebug {
			log.Println("SERVER: 解密指令包失败 , ", err.Error())
		}
		return false
	}
	n := len(dedata)
	if err != nil || n < 21 {
		if isdebug {
			log.Println("SERVER 指令包过短, ", n)
		}
		return false
	}
	/**
	+---------------+--------------+--------------+----------+----------+
	| Random Number | Control Code | Address Type | DST.ADDR | DST.PORT |
	+---------------+--------------+--------------+----------+----------+
	|    16 byte    |    1 byte    |    1 byte    | Variable |  2 byte  |
	+---------------+--------------+--------------+----------+----------+
		Random Number 由客户端生成的唯一随机数,16字节
		Control Code  与socks5相同的控制代码
		Address Type  与socks5相同的地址类型
		DST.ADDR      与socks5相同的地址
		DST.PORT      与socks5相同的端口
	**/

	//分离出的随机数
	nownonce := dedata[0:16]
	if isdebug {
		fmt.Printf("SERVER 收到随机数 nonce: %x\n", nownonce)
	}
	// TCP Method X'01'
	// UDP Method X'03'

	cmode := dedata[16] //CONTROL CODE
	if cmode == 0x01 {
		//解析得到的目标地址
		dstAddr := pubpro.BytesToTcpAddr(dedata[17:n])
		if isdebug {
			fmt.Println("SERVER: 发起TCP连接 -> ", dstAddr.String())
		}
		return procrsstcp(sconn, dstAddr, key, nownonce)
	} else {
		return processudp(sconn, key, nownonce)
	}

}

func procrsstcp(sconn net.Conn, raddr net.TCPAddr, key []byte, nownonce []byte) bool {
	rconn, err2 := net.DialTCP("tcp", nil, &raddr)
	if err2 != nil {
		log.Println("SERVER: 发起TCP连接请求失败 , ", err2.Error())
		return false
	}
	defer rconn.Close()
	//设置服务器连接到目的地的连接的属性
	rconn.SetLinger(0)
	//这是服务器往目标主机之间的连接,通常认为这一段的网络质量是很好的
	//rconn.SetNoDelay(true)
	rconn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(tcpreadtimeout)))
	rconn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(tcpwritetimeout)))
	// 从LOCAL读然后发送到TARGET
	servertotarget := make(chan int, 1)
	go func() {
		defer sconn.Close()
		defer rconn.Close()
		var rcdata int
		var n int
		for {
			dedata, err := mycrypto.DecryptFrom(sconn, key, nownonce)
			if err != nil {
				if isdebug {
					log.Println("SERVER: 从LOCAL读数据错误！, ", err.Error())
				}
				break
			}
			n, err = rconn.Write(dedata)
			if err != nil {
				if isdebug {
					log.Println("服务端: TCP转发来自LOCAL的数据错误！ , ", err.Error())
				}
				break
			}
			rcdata = rcdata + n
		}
		servertotarget <- rcdata
	}()
	//从TARGET读返回到LOCAL
	targettoserver := 0
	buf := make([]byte, mybufsize)
	var ln int
	var err error
	for {
		if ln, err = rconn.Read(buf); err != nil {
			if isdebug {
				log.Println("SERVER 从TARGET读数据错误！, ", err.Error())
			}
			break
		} else {
			targettoserver = targettoserver + ln
			_, err = mycrypto.EncryptTo(buf[:ln], sconn, key, nownonce)
			if err != nil {
				break
			}
		}
	}
	sconn.Close()
	fmt.Println("SERVER TCP CONNECTION ", rconn.RemoteAddr().String(), "  SEND:", pubpro.ReadableBytes(<-servertotarget), "   RECV:", pubpro.ReadableBytes(targettoserver))
	return true
}

func processudp(sconn net.Conn, key []byte, nownonce []byte) bool {
	defer sconn.Close()

	var err1 error
	//本地监听的UDP连接
	var udpconn *net.UDPConn
	//laddr为nil时,监听所有地址和随机选择可用端口
	udpconn, err1 = net.ListenUDP("udp", nil)
	if err1 != nil {
		log.Println("SERVER UDP端口监听启动失败！ , ", err1.Error())
		return false
	}
	//设置UDP连接的最大保持时间
	udpconn.SetDeadline(time.Now().Add(time.Duration(udplivetime) * time.Second))
	//延长SERVER到LOCAL连接的保持时间，这个时间必须不小于UDP连接的存活时间
	sconn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(udplivetime)))
	if isdebug {
		fmt.Println("SERVER 开放UDP端口 -> ", udpconn.LocalAddr().String())
	}

	//目标返回到服务器UDP端口的数据总大小
	targettoserverudp := make(chan int, 1)
	go func() {
		defer sconn.Close()
		defer udpconn.Close()
		var tmprecv int
		var rcn int
		var err2 error
		//储存收到的UDP包的来源地址
		var saddr *net.UDPAddr
		//要返回LOCAL的数据
		var writebuf []byte
		buf := make([]byte, mybufsize)
		for {
			rcn, saddr, err2 = udpconn.ReadFromUDP(buf)
			if err2 != nil {
				if isdebug {
					log.Println("SERVER UDP从目标服务器读数据错误！ , ", err2.Error())
				}
				break
			}
			tmprecv = tmprecv + rcn
			//第一个卡我半天的bug的遗址,方法已经被我重写了,但是错误原因是因为搞错了变量名,导致服务器接收到UDP回包
			//后,构造数据包头时,错误的使用LOCAL请求的目标地址的变量填入了本该写返回数据包源地址的变量，导致SOCKS5客户端
			//接收到的UDP数据包返回地址全是错误的，这就导致了NatTypeTester显示UnsupportSevrer

			//把地址转换成bytes
			writebuf = pubpro.AddrToBytes(saddr.IP, saddr.Port)
			if isdebug {
				fmt.Printf("SERVER 送回UDP数据包: |%x|%x| , %s <- %s\n", writebuf, buf[:rcn], pubpro.ReadableBytes(rcn), saddr.String())
			}
			//通过命令连接送回UDP数据包
			_, err2 := mycrypto.EncryptTo(pubpro.ConnectBytes(writebuf, buf[:rcn]), sconn, key, nownonce)
			if err2 != nil {
				log.Println("SERVER 转发已接收到的UDP数据错误！ , ", err2.Error())
				break
			}
		}
		targettoserverudp <- tmprecv
	}()
	//来自客户端的已解密数据
	var fromlocaldata []byte
	//要发往目标的数据
	var realdata []byte
	var n int
	var servertotargetudp int
	for {
		fromlocaldata, err1 = mycrypto.DecryptFrom(sconn, key, nownonce)
		if err1 != nil {
			if isdebug {
				log.Println("SERVER UoT隧道读数据失败 , ", err1.Error())
			}
			break
		}
		if isdebug {
			fmt.Printf("SERVER 来自LOCAL的UDP数据包 |%x|\n", fromlocaldata)
		}
		//因为UDP数据包带载荷，所以导致我得自己分离出地址，因为必须现场知道长度才能分离出数据
		//UDP数据包要发送到的目标地址
		targetaddr := &net.UDPAddr{}
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
			targetaddr, err1 = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", (fromlocaldata[2:2+int(fromlocaldata[1])]), pubpro.BytesTouInt16(fromlocaldata[2+int(fromlocaldata[1]):2+int(fromlocaldata[1])+2])))
			if err1 != nil {
				if isdebug {
					log.Println("SERVER 处理UDP数据时发生错误: 解析目标网址失败! , ", err1.Error())
				}
			}
		default:
			if isdebug {
				log.Println("SERVER 处理UDP数据时发生错误: 地址类型无法识别! , ", err1.Error())
			}
		}
		if err1 != nil {
			if isdebug {
				log.Printf("此UoT包因错误而被忽略 |%x| ,%s \n", fromlocaldata[:n], err1.Error())
			}
			continue //跳过这个包
		}
		n, err1 = udpconn.WriteToUDP(realdata, targetaddr)
		if err1 != nil {
			log.Println("SERVER 发送UDP数据到目的地失败！ ， ", err1.Error())
			break
		}
		if isdebug {
			fmt.Printf("SERVER 转发来自LOCAL的UDP数据 |%x| , %s -> %s\n", realdata, pubpro.ReadableBytes(n), targetaddr.String())
		}
		servertotargetudp = servertotargetudp + n

	}
	udpconn.Close()
	fmt.Println("UDP 方式 : SEND ", pubpro.ReadableBytes(servertotargetudp), " RECV", pubpro.ReadableBytes(<-targettoserverudp))
	return true
}
