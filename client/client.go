package client

import (
	"fmt"
	"log"
	"net"
	"time"

	"../mycrypto"
	"../pubpro"
)

var mybufsize int = 1024 * 8
var tcpreadtimeout int = 60  //TCP Timeout不要小于 UDP Timeout
var tcpwritetimeout int = 15 //TCP Timeout不要小于 UDP Timeout
var udplivetime int = 600    //TCP Timeout不要小于 UDP Timeout
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

//Client主程序
func Client(socks5listen string, remoteaddr string, key []byte) {
	fmt.Println("SOCKS5监听地址为: ", socks5listen)
	fmt.Println("连接的SERVER地址为: ", remoteaddr)
	ml, err := net.Listen("tcp", socks5listen) //此为在LOCAL开启一个SOCKS5服务器
	if err != nil {
		log.Println("LOCAL SOCKS5监听错误", socks5listen, " , ", err.Error())
		return
	}
	defer ml.Close() //保证退出的时候结束监听这个端口,释放资源
	for {
		aconn, err := ml.Accept()
		if err != nil {
			log.Println("LOCAL SOCKS5接收连接错误,", socks5listen, " , ", err.Error())
			break
		}
		aconn.(*net.TCPConn).SetLinger(0) //接收到一个SOCKS5连接,设置连接异常时立即关闭
		//aconn.(*net.TCPConn).SetNoDelay(true) //设置TCP NO DELEY标志
		aconn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(tcpreadtimeout)))
		aconn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(tcpwritetimeout)))
		go process(aconn, remoteaddr, key) //交给SOCKS5指令处理部分
	}
}

//处理SOCKS5数据
func process(sconn net.Conn, remoteaddr string, key []byte) bool {
	defer sconn.Close()            //保证在出错或任务结束时主动关闭SOCKS5连接
	buf := make([]byte, mybufsize) //读数据的buf
	var n int
	var err error
	/*
	  The client connects to the server, and sends a version
	  identifier/method selection message:

	                  +----+----------+----------+
	                  |VER | NMETHODS | METHODS  |
	                  +----+----------+----------+
	                  | 1  |    1     | 1 to 255 |
	                  +----+----------+----------+

	  The VER field is set to X'05' for this version of the protocol.  The
	  NMETHODS field contains the number of method identifier octets that
	  appear in the METHODS field.
	*/
	// 第一个字段VER代表Socks的版本，Socks5默认为0x05，其固定长度为1个字节

	n, err = sconn.Read(buf)
	// 只支持版本5
	if err != nil || buf[0] != 0x05 {
		if isdebug {
			log.Printf("仅支持socks v5 , |%x|\n", buf[:n])
		}
		//协议错误,关闭连接
		return false
	}

	/**
		   The dstServer selects from one of the methods given in METHODS, and
		   sends a METHOD selection message:

			          +----+--------+
			          |VER | METHOD |
			          +----+--------+
			          | 1  |   1    |
			          +----+--------+

			The values currently defined for METHOD are:

	          o  X'00' NO AUTHENTICATION REQUIRED
	          o  X'01' GSSAPI
	          o  X'02' USERNAME/PASSWORD
	          o  X'03' to X'7F' IANA ASSIGNED
	          o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
	          o  X'FF' NO ACCEPTABLE METHODS

	   The client and server then enter a method-specific sub-negotiation.
	*/
	// 不需要验证，直接验证通过
	sconn.Write([]byte{0x05, 0x00})
	/**
		  +----+-----+-------+------+----------+----------+
		  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		  +----+-----+-------+------+----------+----------+
		  | 1  |  1  | X'00' |  1   | Variable |    2     |
		  +----+-----+-------+------+----------+----------+
	Where:
	          o  VER    protocol version: X'05'
	          o  CMD
	             o  CONNECT X'01'
	             o  BIND X'02'
	             o  UDP ASSOCIATE X'03'
	          o  RSV    RESERVED
	          o  ATYP   address type of following address
	             o  IP V4 address: X'01'
	             o  DOMAINNAME: X'03'
	             o  IP V6 address: X'04'
	          o  DST.ADDR       desired destination address
	          o  DST.PORT desired destination port in network octet
	             order

	   The SOCKS server will typically evaluate the request based on source
	   and destination addresses, and return one or more reply messages, as
	   appropriate for the request type.
	*/

	//此时可以接收来自客户端的指令部分
	n, err = sconn.Read(buf)
	// n 最短的长度为7 情况为 ATYP=3 DST.ADDR占用1字节 值为0x0
	if err != nil || n < 7 {
		if isdebug {
			log.Printf("SOCKS5指令长度过短 |%x|\n", buf[:n])
		}
		//遇到socks5指令错误,断开连接
		return false
	}
	//指令接收到了,现在开始尝试连接至Server端
	serverconn, err := net.Dial("tcp", remoteaddr)
	if err != nil {
		sconn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Println("LOCAL 无法连接至服务器", remoteaddr, " , ", err.Error())
		return false
	}
	err = serverconn.(*net.TCPConn).SetLinger(0) //与server端的连接需要关闭时立即断开连接
	if err != nil {
		sconn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Println("LOCAL 设置与SERVER的连接 连接异常时立即关闭 状态错误 ", remoteaddr, " , ", err.Error())
		return false
	}
	err = serverconn.(*net.TCPConn).SetNoDelay(true) //与server端的连接需要开启TCP NO DELAY标志
	if err != nil {
		sconn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Println("LOCAL 设置与SERVER的连接  TCP NO DELAY 状态错误 ", remoteaddr, " , ", err.Error())
		return false
	}
	//与server端的连接需要设置 读/写 最大超时时间
	serverconn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(tcpreadtimeout)))
	serverconn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(tcpwritetimeout)))
	//保证此进程退出的时候,建立的连接得到释放
	defer serverconn.Close()
	//由客户端生成一个长16字节的随机数,之后将作为协议加密时的AES GCM加密方式 附加验证数据使用
	nownonce := mycrypto.Makenonce()
	if nownonce == nil {
		log.Println("LOCAL 随机数生成失败！")
		return false
	}
	if isdebug {
		fmt.Printf("LOCAL 生成随机数 nonce: %x\n", nownonce)
	}
	/**
		处理数据包成这个样子发往服务器
	+---------------+--------------+--------------+----------+----------+
	| Random Number | Control Code | Address Type | DST.ADDR | DST.PORT |
	+---------------+--------------+--------------+----------+----------+
	|    16 byte    |    1 byte    |    1 byte    | Variable |  2 byte  |
	+---------------+--------------+--------------+----------+----------+
			**/
	//处理好数据后,发送数据到服务器
	//首包用的附加数据为当前时间(精确到分钟),这样防止时间差距太大的重放攻击
	//但是这样的话,服务器和客户端就必须时间无差别,且时区必须一致
	timeStamp := time.Now().Unix()
	timeLayout := "2006-01-02 15:04"
	timeStr := time.Unix(timeStamp, 0).Format(timeLayout)
	var adddata []byte
	adddata, err = mycrypto.Strtokey128(timeStr)
	if err != nil {
		log.Println("LOCAL 生成首包时间戳失败! ,", err.Error())
		return false
	}
	_, err = mycrypto.EncryptTo(pubpro.ConnectBytes(pubpro.ConnectBytes(nownonce, buf[1:2]), buf[3:n]), serverconn, key, adddata)
	if err != nil {
		log.Println("LOCAL 发送指令到SERVER失败！ , ", err.Error())
		return false
	}
	/*

	   The SOCKS request information is sent by the client as soon as it has
	      established a connection to the SOCKS server, and completed the
	      authentication negotiations.  The server evaluates the request, and
	      returns a reply formed as follows:

	           +----+-----+-------+------+----------+----------+
	           |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	           +----+-----+-------+------+----------+----------+
	           | 1  |  1  | X'00' |  1   | Variable |    2     |
	           +----+-----+-------+------+----------+----------+

	        Where:

	             o  VER    protocol version: X'05'
	             o  REP    Reply field:
	                o  X'00' succeeded
	                o  X'01' general SOCKS server failure
	                o  X'02' connection not allowed by ruleset
	                o  X'03' Network unreachable
	                o  X'04' Host unreachable
	                o  X'05' Connection refused
	                o  X'06' TTL expired
	                o  X'07' Command not supported
	                o  X'08' Address type not supported
	                o  X'09' to X'FF' unassigned
	             o  RSV    RESERVED
	             o  ATYP   address type of following address

	*/

	//开始判断socks5申请的连接方法
	switch buf[1] {
	case 0x01:
		// TCP CONNECT方法
		fmt.Printf("LOCAL SOCKS5 [%s] -> TCP CONNECT\n", sconn.RemoteAddr().String())
		//回复socks5接收连接
		sconn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		//开始处理TCP数据
		return processtcp(sconn, serverconn, key, nownonce)
	case 0x03:
		// UDP 方法
		fmt.Printf("LOCAL SOCKS5 [%s] -> UDP ASSOCIATE\n", sconn.RemoteAddr().String())
		//本地SOCKS5 UDP服务连接
		var udpconn *net.UDPConn
		//随机选择一个可用的UDP端口给SOCKS5 UDP服务器用
		udpconn, err = net.ListenUDP("udp", nil)
		if err != nil {
			if isdebug {
				log.Println("SOCKS5 UDP服务器启动失败！ , ", err.Error())
			}
			sconn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			return false
		}
		//方法退出时关闭这个UDP监听端口释放资源
		defer udpconn.Close()
		//设置这个UDP的读写超时
		udpconn.SetDeadline(time.Now().Add(time.Duration(udplivetime) * time.Second))
		//用于UoT的TCP连接要保持存活，所以TCP读超时时间不得短于UDP通道的存活时间
		sconn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(udplivetime)))
		//获取本地IP
		//这个地方是第二个害得我浪费一天找的BUG所在的地方，用pubpro的getip函数，会导致找到的IP是通往公网的那个网卡的IP，会导致数据包无法按原路到达socks5客户端
		//真的是找死我了,真的大半天,早上重构了一下代码
		myip := sconn.LocalAddr().(*net.TCPAddr).IP
		//解析得到的地址和端口数据
		atmp := pubpro.BytesToTcpAddr(buf[3:n])
		//为了完成Fullcone，每个udp都开一个单独的socks5 UDP服务器，因此发送UDP数据的目标仅限申请的IP
		//解析的SOCSK5要发送数据的目标地址和端口
		clientudpaddr := &net.UDPAddr{IP: sconn.RemoteAddr().(*net.TCPAddr).IP, Port: atmp.Port}
		if clientudpaddr.Port == 0 {
			if isdebug {
				log.Println("LOCAL SOCKS5 UDP连接通知的接收端口有误！ , 等待其发出首包再更新地址", atmp.String())
			}
			clientudpaddr = nil
		}
		if isdebug {
			fmt.Println("SOCKS5 客户端UDP接收地址 -> ", clientudpaddr.String())
			fmt.Println("SOCKS5 服务端UDP接收地址 -> ", udpconn.LocalAddr().(*net.UDPAddr).String())
		}
		//构造SOCKS5 UDP返回数据包,返回SOCKS5 UDP应答,准备接收客户端的UDP数据了
		sendtosocks5 := append([]byte{0x05, 0x00, 0x00}, pubpro.AddrToBytes(myip, udpconn.LocalAddr().(*net.UDPAddr).Port)...)
		n, err = sconn.Write(sendtosocks5)
		if err != nil {
			log.Println("LOCAL 无法回应SOCKS5的UDP请求!", err.Error())
			return false
		}
		if isdebug {
			fmt.Printf("LOCAL 发送给SOCKS5客户端的回包： |%x|,%s\n", sendtosocks5, pubpro.ReadableBytes(n))
		}
		//return udpnat.UdpNat(udpconn)
		return processudp(sconn, udpconn, clientudpaddr, serverconn, key, nownonce)
	default:
		// 0x02为BIND方法，我不打算支持，其他就是未定义方法了
		log.Printf("LOCAL Socks5: Unknow Control Code |%x| From <- %s\n", buf[1], sconn.LocalAddr().String())
		if isdebug {
			log.Println("LOCAL 不支持的方法！")
		}
		sconn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return false
	}
}

//处理UDP数据包
func processudp(sconn net.Conn, udpconn *net.UDPConn, udpreturn *net.UDPAddr, serverconn net.Conn, key []byte, nownonce []byte) bool {
	defer sconn.Close()
	defer udpconn.Close()
	defer serverconn.Close()
	//储存LOCAL发送到SERVER的所有UDP数据包的chan
	localtosocks5udp := make(chan int, 1)
	//储存要更新的SOCKS5 UDP客户端接收地址
	newudpreturn := make(chan *net.UDPAddr, 1)
	go func() {
		defer udpconn.Close()
		defer serverconn.Close()
		defer sconn.Close()
		//临时储存从服务器过来的数据大小
		var servertolocaludp int
		var data []byte
		var receerr error
		var n int

		for udpreturn == nil {
			if isdebug {
				log.Println("LOCAL UDP无法找到目标地址,等待首包...")
			}
			udpreturn = <-newudpreturn
			if isdebug {
				log.Println("LOCAL UDP得到首包,地址为 ", udpreturn.String())
			}
		}
		for {
			//从服务器接收到的数据包都是打包好的UDP数据包，到这里加上UDP头部的三字节
			data, receerr = mycrypto.DecryptFrom(serverconn, key, nownonce)
			if receerr != nil {
				if isdebug {
					log.Println("LOCAL 从服务器接收返回数据失败！ , ", receerr.Error())
				}
				break
			}
			data = pubpro.ConnectBytes([]byte{0x00, 0x00, 0x00}, data)
			n, receerr = udpconn.WriteToUDP(data, udpreturn)
			if receerr != nil {
				if isdebug {
					log.Printf("Local 转发返回的UDP数据到 [%s] 失败 , %s\n", udpreturn.String(), receerr.Error())
				}
				break
			}
			if isdebug {
				fmt.Printf("LOCAL 转发至[%s]的UDP带头地址数据包 -> |%x| , %s \n", udpreturn.String(), data, pubpro.ReadableBytes(n))
			}
			servertolocaludp = servertolocaludp + n
		}
		//退出循环就是结束了,同步一下数据
		localtosocks5udp <- servertolocaludp
	}()
	//从socsk5接收到的UDP数据总大小
	var socks5tolocaludp int
	buf := make([]byte, mybufsize)
	var newudprecv *net.UDPAddr
	var rdn int
	var err error
	for {
		//从LOCAL SOCKS5 UDP读数据
		rdn, newudprecv, err = udpconn.ReadFromUDP(buf)
		if err != nil {
			if isdebug {
				log.Println("LOCAL 从Socks5 UDP 读数据出错 , ", err.Error())
			}
			//UDP读出错，直接退出，结束SOCKS5连接
			break
		}
		if udpreturn == nil {
			newudpreturn <- newudprecv
			udpreturn = newudprecv
		}
		socks5tolocaludp = socks5tolocaludp + rdn
		if isdebug {
			fmt.Printf("LOCAL 转发%s的数据包到 SERVER |%x|, 大小:%s\n", newudprecv.String(), buf[3:rdn], pubpro.ReadableBytes(rdn))
		}
		//要去掉头部的三字节0,和服务器那边对应
		_, err = mycrypto.EncryptTo(buf[3:rdn], serverconn, key, nownonce)
		if err != nil {
			if isdebug {
				log.Println("SOCKS5 UDP打包数据加密失败,关闭连接 , ", err.Error())
			}
			break
		}
	}
	serverconn.Close()
	fmt.Println("Local: Socks5 UDP From:  ", udpreturn.String(), " <-  RECV: ", pubpro.ReadableBytes(<-localtosocks5udp), " SEND: ", pubpro.ReadableBytes(socks5tolocaludp))
	return true
}

func processtcp(sconn net.Conn, serverconn net.Conn, key []byte, nownonce []byte) bool {
	defer sconn.Close()
	defer serverconn.Close()
	//储存总共转发到SOCKS5的数据
	localtosocks5tcp := make(chan int, 1)
	/*
		go 有个chan会引发阻塞
		因为从服务器端接受数据比从socks5端接受数据更加危险,所以放在go里的应该是从服务器读数据的进程
		这样一旦读数据出错,直接关闭serverconn退出go引发socks5关闭,进而引发在for里的循环跳出
	*/

	go func() {
		defer sconn.Close()
		defer serverconn.Close()
		//临时储存来自服务器的数据
		var ttr int
		var fromserverdata []byte
		var err2 error
		var tmpwrite int
		for {
			fromserverdata, err2 = mycrypto.DecryptFrom(serverconn, key, nownonce)
			if err2 != nil {
				if isdebug {
					log.Println("Local: 解密来自SERVER的数据失败 , ", err2.Error())
				}
				break
			}
			tmpwrite, err2 = sconn.Write(fromserverdata)
			if err2 != nil {
				if isdebug {
					log.Println("LOCAL: 写入数据到SOCKS5失败 , ", err2.Error())
				}
				break
			}
			ttr = ttr + tmpwrite
		}
		localtosocks5tcp <- ttr //同步接收到的数据
	}()

	//总计从SOCKS5接收到的数据大小
	socks5tolocaltcp := 0
	buf := make([]byte, mybufsize)
	var ln int
	var err error
	//临时的从SOCKS5接收到的数据大小
	for {
		if ln, err = sconn.Read(buf); err != nil {
			if isdebug {
				log.Println("LOCAL 从SOCKS5读取TCP数据失败 , ", err.Error())
			}
			break
		} else {
			_, err = mycrypto.EncryptTo(buf[:ln], serverconn, key, nownonce)
			if err != nil {
				if isdebug {
					log.Println("LOCAL: TCP数据发送到SERVER失败! , ", err.Error())
				}
				break
			}
			socks5tolocaltcp = socks5tolocaltcp + ln
		}
	}
	serverconn.Close()
	fmt.Println("Local: Socks5 TCP From: ", sconn.RemoteAddr().String(), "  SEND:", pubpro.ReadableBytes(socks5tolocaltcp), " RECV:", pubpro.ReadableBytes(<-localtosocks5tcp))
	return true
}
