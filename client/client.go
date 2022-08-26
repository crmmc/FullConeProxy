package client

import (
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"strings"
	"time"

	"../mycrypto"
	"../pubpro"
)

var mybufsize int = 1024 * 4

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
	ServerAddr           net.TCPAddr
	ServerKey            []byte
	ServerFaildTime      int8  //记录服务器连接失败的次数，这样的话失败的次数过多就可以一定时间禁用这个服务器了
	ServerLastFailedTime int64 //记录服务器被禁用解封的时间
}

//不要在这里的Timeout使用time。Time，因为这样的话全部用的都是指向一块内存地址的Time。time，而这个对象在到达指定时间之后就会
//到时间，所有的连接都被设置到这个计时器，就会导致一个计时器到时间，立马让所有使用这个计时器的连接回报IO Timeout错误，导致程序废掉
type AClient struct {
	serverconfig       []ServerConfig
	tcpReadTimeout     int  //TCP Read Timeout
	tcpWriteTimeout    int  //TCP Write Timeout
	udpLifeTime        int  //UDP的ReadWrite Timeout
	tcpNODELAY         bool //TCP的无延迟发送选项
	IsDebug            bool //是否处于调试模式
	ServerChoiceRandom bool //是否随机取服务器，还是按顺序使用服务器，将靠后的服务器作为备份使用
}

func (r *AClient) Init() {
	r.tcpReadTimeout = 60
	r.tcpWriteTimeout = 15
	r.udpLifeTime = 120
	r.tcpNODELAY = true
	r.IsDebug = false
	r.ServerChoiceRandom = true
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
		fmt.Printf("Client使用服务器地址: [%s]", i.ServerAddr.String())
		if r.IsDebug {
			fmt.Printf(" 秘钥: |%x|", i.ServerKey)
		}
		fmt.Println()
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
		go r.process(aconn)            //交给SOCKS5指令处理部分
	}
}

//处理SOCKS5数据
func (r *AClient) process(socks5conn *net.TCPConn) bool {
	defer socks5conn.Close()       //保证在出错或任务结束时主动关闭SOCKS5连接
	buf := make([]byte, mybufsize) //读数据的buf
	var n int
	var err error
	//一个SOCKS5握手怎么能超过5秒是吧，超过就废了它
	socks5conn.SetReadDeadline(time.Now().Add(time.Duration(5) * time.Second))
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
		log.Println("LOCAL 连接到SERVER失败: " + err.Error())
		socks5conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return false
	}
	serverconn.SetLinger(0)             //与server端的连接需要关闭时立即断开连接
	serverconn.SetNoDelay(r.tcpNODELAY) //与server端的连接需要开启TCP NO DELAY标志
	//保证此进程退出的时候,建立的连接得到释放
	defer serverconn.Close()
	//由客户端生成一个长16字节的随机数,之后将作为协议加密时的AES GCM加密方式 附加验证数据使用
	var nownonce []byte
	nownonce, err = mycrypto.Makenonce()
	if err != nil {
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
	//在加密函数那里写了若是附加数据为nil，则自动给包加(时间戳与key)的MD5作为附加数据，这样的话首包的安全性能得到更大保障
	//解包使用类似V2的做法，可以允许LOCAL与SERVER时间相差正负两秒。
	//为了防止对密文固定位置的ATYPE统计学攻击，给ADDRTYPE IPV4分配1到100的数字，IPV6分配100-254的数字，Domain分配255

	switch buf[1] {
	case 0x01:
		// TCP CONNECT方法
		fmt.Printf("SOCKS5: TCP CONNECT [%s]<=>[Local]<=>[%s][SERVER]\n", socks5conn.RemoteAddr().String(), serverconn.RemoteAddr().String())
		//回复socks5接收连接
		socks5conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		//发送首包到服务器
		//客户端发过去的包的adddata都是 0XFF,0XFF
		_, err = mycrypto.EncryptTo(append(append(nownonce, buf[1:2]...), buf[3:n]...), serverconn, key, nil, []byte{0xff, 0xff})
		if err != nil {
			log.Println("LOCAL 发送TCP指令到SERVER失败！ , ", err.Error())
			return false
		}
		//开始处理TCP数据
		return r.processtcp(socks5conn, serverconn, &key, &nownonce)
	case 0x03:
		// UDP 方法
		fmt.Printf("SOCKS5: UDP ASSOCIATE [%s]<=>[Local]<=>[%s][SERVER]\n", socks5conn.RemoteAddr().String(), serverconn.RemoteAddr().String())
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
		//获取本地IP
		//这个地方是第二个害得我浪费一天找的BUG所在的地方，用pubpro的getip函数，会导致找到的IP是通往公网的那个网卡的IP，会导致数据包无法按原路到达socks5客户端
		//真的是找死我了,真的大半天,早上重构了一下代码
		myip := socks5conn.LocalAddr().(*net.TCPAddr).IP
		//解析得到的地址和端口数据
		atmp := pubpro.BytesToTcpAddr(buf[3:n])
		if atmp == nil {
			if r.IsDebug {
				log.Printf("CLIENT 解析UDP地址数据错误 [%x]\n", buf[3:n])
			}
			return false
		}
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
		//UDP首包的地址数据无用，使用随机数据填充以混淆特征
		tmpdata := make([]byte, pubpro.GetRanduInt8())
		_, err = crand.Read(tmpdata)
		if err != nil {
			log.Println("LOCAL 随机数生成失败，无法发送UDP指令到SERVER ", err.Error())
		}
		_, err = mycrypto.EncryptTo(append(append(nownonce, buf[1:2]...), tmpdata...), serverconn, key, nil, []byte{0xff, 0xff})
		if err != nil {
			log.Println("LOCAL 发送TCP指令到SERVER失败！ , ", err.Error())
			return false
		}
		return r.processudp(socks5conn, udpconn, clientudpaddr, serverconn, &key, &nownonce)
	default:
		// 0x02为BIND方法，我不打算支持，其他就是未定义方法了
		log.Printf("Local Socks5: Unknow Control Code |%x| From <- %s\n", buf[1], socks5conn.LocalAddr().String())
		if r.IsDebug {
			log.Println("LOCAL 不支持的方法！")
		}
		socks5conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return false
	}
}

func (r *AClient) ConnectToAServer() (*net.TCPConn, []byte, error) {
	var a net.Conn
	var err error
	//若是开启随机选择服务器，那就把服务器数组打乱
	if r.ServerChoiceRandom && len(r.serverconfig) > 1 {
		mrand.Seed(time.Now().Unix())
		mrand.Shuffle(len(r.serverconfig), func(i int, j int) {
			r.serverconfig[i], r.serverconfig[j] = r.serverconfig[j], r.serverconfig[i]
		})
	}
	for surint := range r.serverconfig {
		//若最后一次失败的时间到现在超过30秒里，那就解放服务器，重置失败次数
		if r.serverconfig[surint].ServerLastFailedTime-time.Now().Unix() > 30 {
			r.serverconfig[surint].ServerFaildTime = 0
			log.Printf("Local: --X->[%s][SERVER] Server Release\n", r.serverconfig[surint].ServerAddr.IP)
		}
		//30秒内失败3次就算寄
		if r.serverconfig[surint].ServerFaildTime > 2 {
			log.Printf("Local: --X->[%s][SERVER] Server Connect Failed Too Many Time, Disable it for 30 second!\n", r.serverconfig[surint].ServerAddr.IP)
			continue
		}
		//连接服务器的超时保持,2秒建立一个TCP连接很困难吗？ 太久会拖累备用服务器的切换体验
		a, err = net.DialTimeout("tcp", r.serverconfig[surint].ServerAddr.String(), time.Duration(2)*time.Second)
		if err == nil {
			return a.(*net.TCPConn), r.serverconfig[surint].ServerKey, err
		}
		//连接服务器失败算一个重要的信息，不能忽略
		log.Printf("Local: --X->[%s][SERVER] Server Connect Failed! Times:%d\n", r.serverconfig[surint].ServerAddr.IP, r.serverconfig[surint].ServerFaildTime)
		r.serverconfig[surint].ServerFaildTime++ //递增失败次数，过多就禁用这个服务器
		r.serverconfig[surint].ServerLastFailedTime = time.Now().Unix()
	}
	return nil, nil, errors.New("无可用的服务器以供选择")
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
			serverconn.SetReadDeadline(time.Now().Add(time.Duration(r.tcpReadTimeout) * time.Second))
			data, receerr = mycrypto.DecryptFrom(serverconn, *key, *nownonce, []byte{0xfc, 0xff})
			if receerr != nil {
				if r.IsDebug && receerr != io.EOF && !strings.Contains(receerr.Error(), "closed") {
					log.Println("LOCAL 从服务器接收返回数据失败！ , ", receerr.Error())
				}
				break
			}
			data = append([]byte{0x00, 0x00, 0x00}, data...)
			udpconn.SetWriteDeadline(time.Now().Add(time.Duration(r.tcpWriteTimeout) * time.Second))
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
		//SOCKS5 TCP READ无限超时，因为UDP不断，TCP不断
		socks5conn.SetReadDeadline(time.Time{})
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
		udpconn.SetReadDeadline(time.Now().Add(time.Duration(r.udpLifeTime) * time.Second))
		rdn, newudprecv, err = udpconn.ReadFromUDP(buf)
		if err != nil {
			if r.IsDebug && err != io.EOF && !strings.Contains(err.Error(), "reset") {
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
		serverconn.SetWriteDeadline(time.Now().Add(time.Duration(r.tcpWriteTimeout) * time.Second))
		//要去掉头部的三字节0,和服务器那边对应
		_, err = mycrypto.EncryptTo(buf[3:rdn], serverconn, *key, *nownonce, []byte{0xff, 0xff})
		if err != nil {
			if r.IsDebug && err != io.EOF && !strings.Contains(err.Error(), "reset") {
				log.Println("SOCKS5 UDP打包数据加密失败,关闭连接 , ", err.Error())
			}
			break
		}
	}
	sip := serverconn.RemoteAddr().String()
	serverconn.Close()
	fmt.Printf("Local: UDP ASSOCIATE [%s]<=>[Local]<=>[%s] SEND:%s RECV:%s\n", udpreturn.String(), sip, pubpro.ReadableBytes(<-localtosocks5udp), pubpro.ReadableBytes(socks5tolocaludp))
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
			serverconn.SetReadDeadline(time.Now().Add(time.Duration(r.tcpReadTimeout) * time.Second))
			fromserverdata, err2 = mycrypto.DecryptFrom(serverconn, *key, *nownonce, []byte{0xfc, 0xff})
			if err2 != nil {
				if r.IsDebug && err2 != io.EOF && !strings.Contains(err2.Error(), "closed") {
					log.Println("Local: 解密来自SERVER的数据失败 , ", err2.Error())
				}
				break
			}
			//fmt.Printf("LOCAL 从服务器接收数据：|%x|->|%d|\n", fromserverdata, len(fromserverdata))
			socks5conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(r.tcpWriteTimeout)))
			tmpwrite, err2 = socks5conn.Write(fromserverdata)
			if err2 != nil && err2 != io.EOF && !strings.Contains(err2.Error(), "closed") {
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
		socks5conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(r.tcpReadTimeout)))
		if ln, err = socks5conn.Read(buf); err != nil {
			if r.IsDebug && err != io.EOF && !strings.Contains(err.Error(), "reset") {
				log.Println("LOCAL 从SOCKS5读取TCP数据失败 , ", err.Error())
			}
			break
		} else {
			//fmt.Printf("LOCAL 发送数据：|%x|->|%d|\n", buf[:ln], ln)
			serverconn.SetWriteDeadline(time.Now().Add(time.Duration(r.tcpWriteTimeout) * time.Second))
			_, err = mycrypto.EncryptTo(buf[:ln], serverconn, *key, *nownonce, []byte{0xff, 0xff})
			if err != nil {
				if r.IsDebug {
					log.Println("LOCAL: TCP数据发送到SERVER失败! , ", err.Error())
				}
				break
			}
			socks5tolocaltcp = socks5tolocaltcp + ln
		}
	}
	//防止连接关闭过早出现nil
	sip := serverconn.RemoteAddr().String()
	cip := socks5conn.RemoteAddr().String()
	serverconn.Close()
	fmt.Printf("Local: TCP CONNECT [%s]<=>[Local]<=>[%s][SERVER] SEND:%s RECV:%s\n", cip, sip, pubpro.ReadableBytes(socks5tolocaltcp), pubpro.ReadableBytes(<-localtosocks5tcp))
	return true
}
