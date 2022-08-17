package client

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"../mycrypto"
	"../pubpro"
)

var mybufsize int = 1024 * 8

func (r *AClient) SetDebug(mode bool) {
	r.IsDebug = mode
}

func (r *AClient) SetTCPReadTimeout(timeout int) {
	r.tcpReadTimeout = timeout
}
func (r *AClient) SetTCPWriteTimeout(timeout int) {
	r.tcpWriteTimeout = timeout
}
func (r *AClient) SetUDPLifeTime(timeout int) {
	r.udpLifeTime = timeout
}

type ServerConfig struct {
	ServerAddr net.TCPAddr
	ServerKey  []byte
}

//不要在这里的Timeout使用time。Time，因为这样的话全部用的都是指向一块内存地址的Time。time，而这个对象在到达指定时间之后就会
//到时间，所有的连接都被设置到这个计时器，就会导致一个计时器到时间，立马让所有使用这个计时器的连接回报IO Timeout错误，导致程序废掉
type AClient struct {
	serverconfig    []ServerConfig
	tcpReadTimeout  int  //TCP Read Timeout
	tcpWriteTimeout int  //TCP Write Timeout
	udpLifeTime     int  //UDP的ReadWrite Timeout
	tcpNODELAY      bool //TCP的无延迟发送选项
	IsDebug         bool //是否处于调试模式
}

func (r *AClient) Init() {
	r.tcpReadTimeout = 60
	r.tcpWriteTimeout = 15
	r.udpLifeTime = 600
	r.tcpNODELAY = true
	r.IsDebug = false
}

//Client主程序
func (r *AClient) StartSocks5(socks5listenaddr string, serverconfig []ServerConfig) {
	fmt.Println("SOCKS5 监听地址：", socks5listenaddr)
	var err error
	var socks5listenTCPaddr *net.TCPAddr
	var socks5listener *net.TCPListener
	socks5listenTCPaddr, err = net.ResolveTCPAddr("tcp", socks5listenaddr)
	if err != nil {
		log.Println("SOCKS5 解析监听地址失败！ ", err.Error(), " ", socks5listenaddr)
		return
	}
	socks5listener, err = net.ListenTCP("tcp", socks5listenTCPaddr) //此为在LOCAL开启一个SOCKS5服务器
	if err != nil {
		log.Println("SOCKS5监听错误", socks5listenaddr, " , ", err.Error())
		return
	}
	defer socks5listener.Close()
	for _, i := range serverconfig {
		fmt.Printf("Client使用服务器地址： %s\n", i.ServerAddr.String())
	}
	r.serverconfig = serverconfig
	for {
		aconn, err := socks5listener.AcceptTCP()
		if err != nil {
			log.Println("LOCAL SOCKS5接受连接错误,", socks5listenaddr, " , ", err.Error())
			break
		}
		aconn.SetLinger(0)             //接收到一个SOCKS5连接,设置连接异常时立即关闭
		aconn.SetNoDelay(r.tcpNODELAY) //设置TCP NO DELEY标志
		aconn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(r.tcpReadTimeout)))
		aconn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(r.tcpWriteTimeout)))
		go r.process(aconn) //交给SOCKS5指令处理部分
	}
}

//处理SOCKS5数据
func (r *AClient) process(socks5conn *net.TCPConn) bool {
	defer socks5conn.Close()       //保证在出错或任务结束时主动关闭SOCKS5连接
	buf := make([]byte, mybufsize) //读数据的buf
	var n int
	var err error
	n, err = socks5conn.Read(buf)
	// 只支持版本5
	if err != nil || buf[0] != 0x05 {
		if r.IsDebug {
			log.Printf("仅支持Socks Version 5 , |%x|\n", buf[:n])
		}
		//协议错误,关闭连接
		return false
	}
	socks5conn.Write([]byte{0x05, 0x00})

	//此时可以接收来自客户端的指令部分
	n, err = socks5conn.Read(buf)
	// n 最短的长度为7 情况为 ATYP=3 DST.ADDR占用1字节 值为0x0
	if err != nil || n < 7 {
		if r.IsDebug {
			log.Printf("SOCKS5 指令长度过短 |%x|\n", buf[:n])
		}
		//遇到socks5指令错误,断开连接
		return false
	}
	var serverconn *net.TCPConn
	var key []byte
	//指令接收到了,现在开始尝试连接至Server端
	serverconn, key, err = r.ConnectToAServer()
	if err != nil {
		log.Println(err.Error())
		socks5conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return false
	}
	serverconn.SetLinger(0)             //与server端的连接需要关闭时立即断开连接
	serverconn.SetNoDelay(r.tcpNODELAY) //与server端的连接需要开启TCP NO DELAY标志
	//与server端的连接需要设置 读/写 最大超时时间
	serverconn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(r.tcpReadTimeout)))
	serverconn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(r.tcpWriteTimeout)))
	//保证此进程退出的时候,建立的连接得到释放
	defer serverconn.Close()
	//由客户端生成一个长16字节的随机数,之后将作为协议加密时的AES GCM加密方式 附加验证数据使用
	nownonce := mycrypto.Makenonce()
	if nownonce == nil {
		log.Println("LOCAL 随机数生成失败！")
		return false
	}
	if r.IsDebug {
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
	switch buf[1] {
	case 0x01:
		// TCP CONNECT方法
		fmt.Printf("SOCKS5 [%s] -> TCP CONNECT\n", socks5conn.RemoteAddr().String())
		//回复socks5接收连接
		socks5conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		//开始处理TCP数据
		return r.processtcp(socks5conn, serverconn, &key, &nownonce)
	case 0x03:
		// UDP 方法
		fmt.Printf("SOCKS5 [%s] -> UDP ASSOCIATE\n", socks5conn.RemoteAddr().String())
		//本地SOCKS5 UDP服务连接
		var udpconn *net.UDPConn
		//随机选择一个可用的UDP端口给SOCKS5 UDP服务器用
		udpconn, err = net.ListenUDP("udp", nil)
		if err != nil {
			if r.IsDebug {
				log.Println("SOCKS5 UDP服务器启动失败！ , ", err.Error())
			}
			socks5conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			return false
		}
		//方法退出时关闭这个UDP监听端口释放资源
		defer udpconn.Close()
		//设置这个UDP的读写超时
		udpconn.SetDeadline(time.Now().Add(time.Second * time.Duration(r.udpLifeTime)))
		//用于UoT的TCP连接要保持存活，所以TCP读超时时间不得短于UDP通道的存活时间
		socks5conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(r.udpLifeTime)))
		//获取本地IP
		//这个地方是第二个害得我浪费一天找的BUG所在的地方，用pubpro的getip函数，会导致找到的IP是通往公网的那个网卡的IP，会导致数据包无法按原路到达socks5客户端
		//真的是找死我了,真的大半天,早上重构了一下代码
		myip := socks5conn.LocalAddr().(*net.TCPAddr).IP
		//解析得到的地址和端口数据
		atmp := pubpro.BytesToTcpAddr(buf[3:n])
		//为了完成Fullcone，每个udp都开一个单独的socks5 UDP服务器，因此发送UDP数据的目标仅限申请的IP
		//解析的SOCSK5要发送数据的目标地址和端口
		clientudpaddr := &net.UDPAddr{IP: socks5conn.RemoteAddr().(*net.TCPAddr).IP, Port: atmp.Port}
		if clientudpaddr.Port == 0 {
			if r.IsDebug {
				log.Println("LOCAL SOCKS5 UDP连接通知的接收端口有误！ , 等待其发出首包再更新地址", atmp.String())
			}
			clientudpaddr = nil
		}
		if r.IsDebug {
			fmt.Println("SOCKS5 客户端UDP接收地址 -> ", clientudpaddr.String())
			fmt.Printf("SOCKS5 服务端UDP接收地址 -> %s:%d\n", myip, udpconn.LocalAddr().(*net.UDPAddr).Port)
		}
		//构造SOCKS5 UDP返回数据包,返回SOCKS5 UDP应答,准备接收客户端的UDP数据了
		_, err = socks5conn.Write(append([]byte{0x05, 0x00, 0x00}, pubpro.AddrToBytes(myip, udpconn.LocalAddr().(*net.UDPAddr).Port)...))
		if err != nil {
			log.Println("LOCAL 无法回应SOCKS5的UDP请求!", err.Error())
			return false
		}
		//return udpnat.UdpNat(udpconn) //本地Fullcone NAT测试func
		return r.processudp(socks5conn, udpconn, clientudpaddr, serverconn, &key, &nownonce)
	default:
		// 0x02为BIND方法，我不打算支持，其他就是未定义方法了
		log.Printf("LOCAL Socks5: Unknow Control Code |%x| From <- %s\n", buf[1], socks5conn.LocalAddr().String())
		if r.IsDebug {
			log.Println("LOCAL 不支持的方法！")
		}
		socks5conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return false
	}
}

func (r *AClient) ConnectToAServer() (*net.TCPConn, []byte, error) {
	var a *net.TCPConn
	var err error
	for _, i := range r.serverconfig {
		a, err = net.DialTCP("tcp", nil, &i.ServerAddr)
		if err == nil {
			return a, i.ServerKey, err
		}
	}
	return nil, nil, errors.New("未找到可用的服务器配置！")
}

//处理UDP数据包
func (r *AClient) processudp(socks5conn *net.TCPConn, udpconn *net.UDPConn, udpreturn *net.UDPAddr, serverconn *net.TCPConn, key *[]byte, nownonce *[]byte) bool {
	defer socks5conn.Close()
	defer udpconn.Close()
	defer serverconn.Close()
	//储存LOCAL发送到SERVER的所有UDP数据包的chan
	localtosocks5udp := make(chan int, 1)
	//储存要更新的SOCKS5 UDP客户端接收地址
	newudpreturn := make(chan *net.UDPAddr, 1)
	go func() {
		defer udpconn.Close()
		defer socks5conn.Close()
		defer serverconn.Close()
		//临时储存从服务器过来的数据大小
		var servertolocaludp int
		var data []byte
		var receerr error
		var n int

		for udpreturn == nil {
			if r.IsDebug {
				log.Println("LOCAL UDP无法找到目标地址,等待首包...")
			}
			udpreturn = <-newudpreturn
			if r.IsDebug {
				log.Println("LOCAL UDP得到首包,地址为 ", udpreturn.String())
			}
		}
		for {
			//从服务器接收到的数据包都是打包好的UDP数据包，到这里加上UDP头部的三字节
			data, receerr = mycrypto.DecryptFrom(serverconn, *key, *nownonce)
			if receerr != nil {
				if r.IsDebug {
					log.Println("LOCAL 从服务器接收返回数据失败！ , ", receerr.Error())
				}
				break
			}
			data = pubpro.ConnectBytes([]byte{0x00, 0x00, 0x00}, data)
			n, receerr = udpconn.WriteToUDP(data, udpreturn)
			if receerr != nil {
				if r.IsDebug {
					log.Printf("Local 转发返回的UDP数据到 [%s] 失败 , %s\n", udpreturn.String(), receerr.Error())
				}
				break
			}
			if r.IsDebug {
				fmt.Printf("LOCAL 转发至[%s]的UDP带头地址数据包 -> |%x| , %s \n", udpreturn.String(), data, pubpro.ReadableBytes(n))
			}
			servertolocaludp = servertolocaludp + n
		}
		//退出循环就是结束了,同步一下数据
		localtosocks5udp <- servertolocaludp
	}()
	//UDP模式下，必须保证SOCKS5的TCP连接可用，才代表和SOCKS5客户端UDP保持连接，所以开一个协程循环read保持TCP连接的存活
	go func() {
		defer socks5conn.Close()
		defer serverconn.Close()
		defer udpconn.Close()
		buf := make([]byte, 4)
		var err error
		for {
			_, err = socks5conn.Read(buf)
			if err != nil {
				return
			}
		}
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
			if r.IsDebug {
				log.Println("LOCAL 从Socks5 UDP 读数据出错 , ", err.Error())
			}
			//UDP读出错，直接退出，结束SOCKS5连接
			break
		}
		if udpreturn == nil {
			newudpreturn <- newudprecv
			udpreturn = newudprecv
			if r.IsDebug {
				log.Println("成功同步SOCKS5 UDP发送目标地址 ->", udpreturn.String())
			}
		}
		socks5tolocaludp = socks5tolocaludp + rdn
		if r.IsDebug {
			fmt.Printf("LOCAL 转发%s的数据包到 SERVER |%x|, 大小:%s\n", newudprecv.String(), buf[3:rdn], pubpro.ReadableBytes(rdn))
		}
		//要去掉头部的三字节0,和服务器那边对应
		_, err = mycrypto.EncryptTo(buf[3:rdn], serverconn, *key, *nownonce)
		if err != nil {
			if r.IsDebug {
				log.Println("SOCKS5 UDP打包数据加密失败,关闭连接 , ", err.Error())
			}
			break
		}
	}
	serverconn.Close()
	fmt.Println("Local: Socks5 UDP From:  ", udpreturn.String(), " <-  RECV: ", pubpro.ReadableBytes(<-localtosocks5udp), " SEND: ", pubpro.ReadableBytes(socks5tolocaludp))
	return true
}

func (r *AClient) processtcp(socks5conn *net.TCPConn, serverconn *net.TCPConn, key *[]byte, nownonce *[]byte) bool {
	defer socks5conn.Close()
	defer serverconn.Close()
	//储存总共转发到SOCKS5的数据
	localtosocks5tcp := make(chan int, 1)
	/*
		go 有个chan会引发阻塞
		因为从服务器端接受数据比从socks5端接受数据更加危险,所以放在go里的应该是从服务器读数据的进程
		这样一旦读数据出错,直接关闭serverconn退出go引发socks5关闭,进而引发在for里的循环跳出
	*/

	go func() {
		defer serverconn.Close()
		defer serverconn.Close()
		//临时储存来自服务器的数据
		var ttr int
		var fromserverdata []byte
		var err2 error
		var tmpwrite int
		for {
			fromserverdata, err2 = mycrypto.DecryptFrom(serverconn, *key, *nownonce)
			if err2 != nil {
				if r.IsDebug {
					log.Println("Local: 解密来自SERVER的数据失败 , ", err2.Error())
				}
				break
			}
			tmpwrite, err2 = socks5conn.Write(fromserverdata)
			if err2 != nil {
				if r.IsDebug {
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

		if ln, err = socks5conn.Read(buf); err != nil {
			if r.IsDebug {
				log.Println("LOCAL 从SOCKS5读取TCP数据失败 , ", err.Error())
			}
			break
		} else {
			_, err = mycrypto.EncryptTo(buf[:ln], serverconn, *key, *nownonce)
			if err != nil {
				if r.IsDebug {
					log.Println("LOCAL: TCP数据发送到SERVER失败! , ", err.Error())
				}
				break
			}
			socks5tolocaltcp = socks5tolocaltcp + ln
		}
	}
	serverconn.Close()
	fmt.Println("Local: Socks5 TCP From: ", serverconn.RemoteAddr().String(), "  SEND:", pubpro.ReadableBytes(socks5tolocaltcp), " RECV:", pubpro.ReadableBytes(<-localtosocks5tcp))
	return true
}
