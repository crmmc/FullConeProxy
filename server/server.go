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

//一个Server
type AServer struct {
	listener        net.Listener //私有，AServer的监听
	keybyte         []byte       //私有，储存秘钥数据
	tcpReadTimeout  int          //TCP Read Timeout
	tcpWriteTimeout int          //TCP Write Timeout
	udpLifeTime     int          //UDP的ReadWrite Timeout
	tcpNODELAY      bool         //TCP的无延迟发送选项
	Isdebug         bool         //是否处于调试模式
}

func (r *AServer) Init() {
	r.listener = nil
	r.keybyte = nil
	r.tcpReadTimeout = 60
	r.tcpWriteTimeout = 15
	r.udpLifeTime = 600
	r.tcpNODELAY = true
	r.Isdebug = false
}

func (r *AServer) SetDebug(id bool) {
	r.Isdebug = id
}
func (r *AServer) SetTCPReadTimeout(timeout int) {
	r.tcpReadTimeout = timeout
}
func (r *AServer) SetTCPWriteTimeout(timeout int) {
	r.tcpWriteTimeout = timeout
}
func (r *AServer) SetUDPLifeTime(timeout int) {
	r.udpLifeTime = timeout
}

func (r *AServer) StartServer(locallisten string, key []byte) error {
	fmt.Println("启动SERVER,监听地址为 ->", locallisten)
	sl, err := net.Listen("tcp", locallisten)
	if err != nil {
		log.Println("SERVER监听错误 ->", locallisten, " , ", err.Error())
		return err
	}
	r.listener = sl
	r.keybyte = key
	fmt.Printf("SERVER使用秘钥: |%x|\n", r.keybyte)
	return nil
}

func (r *AServer) Close() {
	if r.listener != nil {
		r.listener.Close()
	}
}

//分开来的原因，是有时候需要创建大量服务器之后再开始监听，分步做应该会快点？
func (r *AServer) StartLoop() error {
	defer r.Close()
	for {
		sconn, err := r.listener.Accept()
		if err != nil {
			log.Printf("SERVER %s 在接受连接时出现错误! %s\n", r.listener.Addr().String(), err.Error())
			return err
		}
		sconn.(*net.TCPConn).SetLinger(0)
		sconn.(*net.TCPConn).SetNoDelay(r.tcpNODELAY)
		sconn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(r.tcpWriteTimeout)))
		sconn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(r.tcpReadTimeout)))
		var pc1 processer
		//此处的变量一直不会改变值，所以传递指针
		pc1.Isdebug = &r.Isdebug
		pc1.TcpReadTimeout = &r.tcpReadTimeout
		pc1.TcpWriteTimeout = &r.tcpWriteTimeout
		pc1.UdpLifeTime = &r.udpLifeTime
		//服务器连接到目标这一段网络的质量通常认为是很好的，所以不需要开启这个选项
		pc1.TcpNODELAY = &r.tcpNODELAY
		go pc1.Process(sconn, r.keybyte)
	}
}

type processer struct {
	connfromclient  *net.TCPConn
	tcptotarget     *net.TCPConn
	udptotarget     *net.UDPConn
	keybyte         *[]byte
	nonce           []byte
	Isdebug         *bool
	TcpReadTimeout  *int  //TCP Read Timeout
	TcpWriteTimeout *int  //TCP Write Timeout
	UdpLifeTime     *int  //UDP的ReadWrite Timeout
	TcpNODELAY      *bool //TCP的无延迟发送选项

}

func (r *processer) Close() {
	if r.connfromclient != nil {
		r.connfromclient.Close()
	}
	if r.tcptotarget != nil {
		r.tcptotarget.Close()
	}
	if r.udptotarget != nil {
		r.udptotarget.Close()
	}
}

//命令处理
func (r *processer) Process(sconn net.Conn, key []byte) bool {
	defer r.Close()
	//此进程一般不会退出除非处理完成，所以传递指针
	r.connfromclient = sconn.(*net.TCPConn)
	r.keybyte = &key
	//生成现在的时间戳，解密首包
	timeStamp := time.Now().Unix()
	timeLayout := "2006-01-02 15:04"
	timeStr := time.Unix(timeStamp, 0).Format(timeLayout)
	//首包的附加消息
	var adddata []byte
	var err error
	adddata, err = mycrypto.Strtokey128(timeStr)
	if err != nil {
		log.Println("SERVER 生成首包时间戳失败! ,", err.Error())
		return false
	}
	//解密出来的完整首包数据
	var dedata []byte
	dedata, err = mycrypto.DecryptFrom(sconn, key, adddata)
	if err != nil {
		if *r.Isdebug {
			log.Println("SERVER: 解密指令包失败 , ", err.Error())
		}
		return false
	}
	//首包数据长度
	n := len(dedata)
	if err != nil || n < 21 {
		if *r.Isdebug {
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
	r.nonce = dedata[0:16]
	if *r.Isdebug {
		fmt.Printf("SERVER 收到随机数 nonce: %x\n", r.nonce)
	}
	// TCP Method X'01'
	// UDP Method X'03'
	if dedata[16] == 0x01 {
		//解析得到的目标地址
		dstAddr := pubpro.BytesToTcpAddr(dedata[17:n])
		if *r.Isdebug {
			fmt.Println("SERVER: 发起TCP连接 -> ", dstAddr.String())
		}
		//这一进程不会退出，所以发送过去数据指针
		return r.procrsstcp(&dstAddr)
	} else {
		return r.processudp()
	}

}

func (r *processer) procrsstcp(raddr *net.TCPAddr) bool {
	defer r.Close()
	var err2 error
	r.tcptotarget, err2 = net.DialTCP("tcp", nil, raddr)
	if err2 != nil {
		log.Println("SERVER: 发起TCP连接请求失败 , ", err2.Error())
		return false
	}
	//设置服务器连接到目的地的连接的属性
	r.tcptotarget.SetLinger(0)
	r.tcptotarget.SetNoDelay(*r.TcpNODELAY)
	r.tcptotarget.SetReadDeadline(time.Now().Add(time.Second * time.Duration(*r.TcpReadTimeout)))
	r.tcptotarget.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(*r.TcpWriteTimeout)))
	// 从LOCAL读然后发送到TARGET
	servertotarget := make(chan int, 1)
	go func() {
		defer r.Close()
		var rcdata int
		//往目标写入的数据的大小
		var n int
		//从客户端读到的TCP数据
		var dedata []byte
		var err error
		for {
			dedata, err = mycrypto.DecryptFrom(r.connfromclient, *r.keybyte, r.nonce)
			if err != nil {
				if *r.Isdebug {
					log.Println("SERVER: 从LOCAL读数据错误！, ", err.Error())
				}
				break
			}
			n, err = r.tcptotarget.Write(dedata)
			if err != nil {
				if *r.Isdebug {
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
	//从Target读到的数据
	buf := make([]byte, mybufsize)
	//从Target读到的数据大小
	var ln int
	var err error
	for {
		if ln, err = r.tcptotarget.Read(buf); err != nil {
			if *r.Isdebug {
				log.Println("SERVER 从TARGET读数据错误！, ", err.Error())
			}
			break
		} else {
			targettoserver = targettoserver + ln
			_, err = mycrypto.EncryptTo(buf[:ln], r.connfromclient, *r.keybyte, r.nonce)
			if err != nil {
				break
			}
		}
	}
	//防止后面close后这个变量消失，这里新建一个变量存着Target的地址数据
	TCPTOaddr := r.tcptotarget.RemoteAddr().String()
	r.Close()
	fmt.Println("SERVER TCP CONNECTION ", TCPTOaddr, "  SEND:", pubpro.ReadableBytes(<-servertotarget), "   RECV:", pubpro.ReadableBytes(targettoserver))
	return true
}

func (r *processer) processudp() bool {
	defer r.Close()

	var err1 error
	//laddr为nil时,监听所有地址和随机选择可用端口
	r.udptotarget, err1 = net.ListenUDP("udp", nil)
	if err1 != nil {
		log.Println("SERVER UDP端口监听启动失败！ , ", err1.Error())
		return false
	}
	//设置UDP连接的最大保持时间
	r.udptotarget.SetDeadline(time.Now().Add(time.Second * time.Duration(*r.UdpLifeTime)))
	//延长SERVER到LOCAL连接的保持时间，这个时间必须不小于UDP连接的存活时间
	r.connfromclient.SetReadDeadline(time.Now().Add(time.Second * time.Duration(*r.UdpLifeTime)))
	if *r.Isdebug {
		fmt.Println("SERVER 开放UDP端口 -> ", r.udptotarget.LocalAddr().String())
	}

	//目标返回到服务器UDP端口的数据总大小
	targettoserverudp := make(chan int, 1)
	go func() {
		defer r.Close()
		//临时收到的数据总大小
		var tmprecv int
		//现在这个包的数据大小
		var rcn int
		var err2 error
		//储存收到的UDP包的来源地址
		var saddr *net.UDPAddr
		//要返回LOCAL的数据
		var writebuf []byte
		buf := make([]byte, mybufsize)
		for {
			rcn, saddr, err2 = r.udptotarget.ReadFromUDP(buf)
			if err2 != nil {
				if *r.Isdebug {
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
			if *r.Isdebug {
				fmt.Printf("SERVER 送回UDP数据包: |%x|%x| , %s <- %s\n", writebuf, buf[:rcn], pubpro.ReadableBytes(rcn), saddr.String())
			}
			//通过命令连接送回UDP数据包
			_, err2 := mycrypto.EncryptTo(pubpro.ConnectBytes(writebuf, buf[:rcn]), r.connfromclient, *r.keybyte, r.nonce)
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
	//从LOCAL收到的总数据大小含包头
	var n int
	//SERVER发往Target的总数据包大小
	var servertotargetudp int
	for {
		fromlocaldata, err1 = mycrypto.DecryptFrom(r.connfromclient, *r.keybyte, r.nonce)
		if err1 != nil {
			if *r.Isdebug {
				log.Println("SERVER UoT隧道读数据失败 , ", err1.Error())
			}
			break
		}
		if *r.Isdebug {
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
				if *r.Isdebug {
					log.Println("SERVER 处理UDP数据时发生错误: 解析目标网址失败! , ", err1.Error())
				}
			}
		default:
			if *r.Isdebug {
				log.Println("SERVER 处理UDP数据时发生错误: 地址类型无法识别! , ", err1.Error())
			}
		}
		if err1 != nil {
			if *r.Isdebug {
				log.Printf("此UoT包因错误而被忽略 |%x| ,%s \n", fromlocaldata[:n], err1.Error())
			}
			continue //跳过这个包
		}
		n, err1 = r.udptotarget.WriteToUDP(realdata, targetaddr)
		if err1 != nil {
			log.Println("SERVER 发送UDP数据到目的地失败！ ， ", err1.Error())
			break
		}
		if *r.Isdebug {
			fmt.Printf("SERVER 转发来自LOCAL的UDP数据 |%x| , %s -> %s\n", realdata, pubpro.ReadableBytes(n), targetaddr.String())
		}
		servertotargetudp = servertotargetudp + n

	}
	r.Close()
	fmt.Println("UDP 方式 : SEND ", pubpro.ReadableBytes(servertotargetudp), " RECV", pubpro.ReadableBytes(<-targettoserverudp))
	return true
}
