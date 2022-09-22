package server

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"../mycrypto"
	"../pubpro"
)

var mybufsize int = 1024 * 4

//全局的Nonce记录，这个用来检测重放,存放在有效期内已存在的IV
var noncerecord map[[16]byte]int64

//nonce记录的操作锁
var noncerecordlock sync.Mutex = sync.Mutex{}

//IV最久保持10秒就过期,这个一定要不短于mycrypto中的时间误差允许范围
var maxrecordtime int64 = 10

//清理IV黑名单的时间，每15秒检查一次，合理设置能减轻随机数表大小且不过分耗费性能
var checktime int = 15

var checkerrunning = false

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
	r.udpLifeTime = 120
	r.tcpNODELAY = true
	r.Isdebug = false
	noncerecord = make(map[[16]byte]int64)
	//启动这个全局检查的goruntime，启动一遍就够了
	if !checkerrunning {
		if r.Isdebug {
			go noncenum()
		}
		go noncechecker()
		checkerrunning = true
	}
}

//单独写Hangon，这样的话就可以让Go释放原来占用的内存空间，只剩下本次连接用的内存空间
func HangOnConnect(hangedconn *net.TCPConn, tcpreadtimeout int) {
	defer hangedconn.Close()
	log.Printf("SERVER 来自[%s]的重放连接被挂起", hangedconn.RemoteAddr().String())
	buf := make([]byte, 10)
	var err error
	var rdn int
	starttime := time.Now().Unix()
	//设置读超时时间点,保证超时时间和正常一致
	hangedconn.SetReadDeadline(time.Now().Add(time.Duration(tcpreadtimeout) * time.Second))
	for {
		rdn, err = hangedconn.Read(buf)
		if err != nil {
			log.Printf("SERVER 重放连接[%s]结束! 持续时间[%d秒] ERROR:[%s]\n", hangedconn.RemoteAddr().String(), time.Now().Unix()-starttime, err.Error())
			return
		}
		log.Printf("来自[%s]的重放数据: |%x| %s\n", hangedconn.RemoteAddr().String(), buf[:rdn], pubpro.ReadableBytes(rdn))
	}
}

//noncerecord统计员
func noncenum() {
	for {
		fmt.Println("Nonce废纸篓数量:", len(noncerecord))
		time.Sleep(time.Duration(2) * time.Second)
	}
}

//noncerecord清理卫士
func noncechecker() {
	mycrypto.SetMaxAllowTimeError(maxrecordtime)
	for {
		nowtime := time.Now().Unix()
		//遍历key，过期的IV记录
		noncerecordlock.Lock()
		for m := range noncerecord {
			if noncerecord[m]-nowtime > maxrecordtime {
				delete(noncerecord, m)
			}
		}
		noncerecordlock.Unlock()
		//太过频繁的轮询消耗机器资源
		time.Sleep(time.Duration(checktime) * time.Second)
	}
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

//申请监听一个服务器
func (r *AServer) StartServer(locallisten string, key []byte) error {
	fmt.Println("启动SERVER,监听地址为 ->", locallisten)
	sl, err := net.Listen("tcp", locallisten)
	if err != nil {
		log.Println("SERVER监听错误 ->", locallisten, " , ", err.Error())
		return err
	}
	r.listener = sl
	r.keybyte = key
	if r.Isdebug {
		fmt.Printf("SERVER使用秘钥: |%x|\n", r.keybyte)
	}
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
		connfromclient, err := r.listener.Accept()
		if err != nil {
			log.Printf("SERVER %s 在接受连接时出现错误! %s\n", r.listener.Addr().String(), err.Error())
			return err
		}
		connfromclient.(*net.TCPConn).SetLinger(0)
		connfromclient.(*net.TCPConn).SetNoDelay(r.tcpNODELAY)
		var pc1 processer
		//此处的变量一直不会改变值，所以传递指针
		pc1.Isdebug = &r.Isdebug
		pc1.TcpReadTimeout = &r.tcpReadTimeout
		pc1.TcpWriteTimeout = &r.tcpWriteTimeout
		pc1.UdpLifeTime = &r.udpLifeTime
		//服务器连接到目标这一段网络的质量通常认为是很好的，所以不需要开启这个选项
		pc1.TcpNODELAY = &r.tcpNODELAY
		go pc1.Process(connfromclient, r.keybyte)
	}
}

type processer struct {
	connfromclient  *net.TCPConn
	tcptotarget     *net.TCPConn
	udptotarget     *net.UDPConn
	keybyte         *[]byte
	nonce           []byte
	Isdebug         *bool
	TcpReadTimeout  *int        //TCP Read Timeout
	TcpWriteTimeout *int        //TCP Write Timeout
	UdpLifeTime     *int        //UDP的ReadWrite Timeout
	TcpNODELAY      *bool       //TCP的无延迟发送选项
	processcipher   cipher.AEAD //用于加解密的cipher

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

//处理并分发请求
func (r *processer) Process(sconn net.Conn, key []byte) bool {
	defer r.Close()
	//此进程一般不会退出除非处理完成，所以传递指针
	r.connfromclient = sconn.(*net.TCPConn)
	r.keybyte = &key
	block, err := aes.NewCipher(key) //生成加解密用的block
	if err != nil {
		log.Println("Server Process 新建AES对象失败" + err.Error())
		return false
	}
	//根据不同加密算法，也有不同tag长度的方法设定和调用，比如NewGCMWithTagSize、newGCMWithNonceAndTagSize
	r.processcipher, err = cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		log.Println("Server Process 设置AES对象失败" + err.Error())
		return false
	}
	//解密出来的完整首包数据
	var dedata []byte
	//在加密函数那里写了若是附加数据为nil，则自动给包加(时间戳与key)的MD5作为附加数据，这样的话首包的安全性能得到更大保障
	//解包使用类似V2的做法，可以允许LOCAL与SERVER时间相差正负两秒,若是nownonce为nil，则自动使用(当前正负两秒共计四个时间戳分别与key)的MD5作为附加数据验证，这样允许客户端与服务端有时间误差，消耗性能换安全性
	r.connfromclient.SetReadDeadline(time.Now().Add(time.Duration(*r.TcpReadTimeout) * time.Second))
	dedata, err = mycrypto.DecryptFrom(r.connfromclient, key, nil, []byte{0xff, 0xff}, r.processcipher)
	if err != nil {
		log.Printf("SERVER: 握手失败 [%s]--x->[SERVER] ERROR:[%s]\n", r.connfromclient.RemoteAddr().String(), err.Error())
		return false
	}
	//首包数据长度
	n := len(dedata)
	if err != nil || n < 20 {
		if *r.Isdebug {
			log.Println("SERVER 指令包过短, 可能遭受逐字节重放，启用应对策略", n)
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
	//用于检测的随机数的copy,golang中切片和数组不是同一类，要复制一个数组副本用
	var pdnonce [16]byte
	copy(pdnonce[:], dedata[0:16])
	//map线程不安全读写都要加锁
	noncerecordlock.Lock()
	if _, ok := noncerecord[pdnonce]; ok {
		log.Println("遭到重放攻击！！ 启用应对措施： 直接重置连接")
		log.Printf("来自： %s 的重放数据包 |%x| ,%s", r.connfromclient.RemoteAddr().String(), dedata, pubpro.ReadableBytes(len(dedata)))
		//挂起连接，但是防止process退出导致process的自动关闭连接触发
		//r.connfromclient = nil
		//go HangOnConnect(sconn.(*net.TCPConn), *r.TcpReadTimeout)
		//统一特征
		return false
	} else {
		noncerecord[pdnonce] = time.Now().Unix()
	}
	noncerecordlock.Unlock()
	if *r.Isdebug {
		fmt.Printf("SERVER 收到随机数 nonce: %x\n", r.nonce)
	}
	// TCP Method X'01'
	// UDP Method X'03'
	if dedata[16] == 0x01 {
		dstAddr := pubpro.BytesToTcpAddr(dedata[17:n])
		if dstAddr == nil {
			if *r.Isdebug {
				log.Printf("SERVER: 客户端请求了错误的地址数据 [%x] ,主动关闭连接.\n", dedata[17:n])
			}
			return false
		}
		fmt.Printf("SERVER: TCP CONNECT [%s]->[SERVER]->[%s]\n", r.connfromclient.RemoteAddr().String(), dstAddr.String())
		//这一进程不会退出，所以发送过去数据指针
		return r.procrsstcp(dstAddr)
	} else {
		fmt.Printf("SERVER: UDP ASSOCIATE [%s]->[SERVER]->[?]\n", r.connfromclient.RemoteAddr().String())
		return r.processudp()
	}

}

//接管处理TCP请求
func (r *processer) procrsstcp(raddr *net.TCPAddr) bool {
	defer r.Close()
	var err2 error
	var dialed net.Conn
	//超时时间是和TCP Write一样的
	dialed, err2 = net.DialTimeout("tcp", raddr.String(), time.Duration(*r.TcpWriteTimeout)*time.Second)
	if err2 != nil {
		log.Println("SERVER: 发起TCP连接请求失败 , ", err2.Error())
		return false
	}
	r.tcptotarget = dialed.(*net.TCPConn)
	//设置服务器连接到目的地的连接的属性
	r.tcptotarget.SetLinger(0)
	r.tcptotarget.SetNoDelay(*r.TcpNODELAY)
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
			r.connfromclient.SetReadDeadline(time.Now().Add(time.Duration(*r.TcpReadTimeout) * time.Second))
			dedata, err = mycrypto.DecryptFrom(r.connfromclient, *r.keybyte, r.nonce, []byte{0xff, 0xff}, r.processcipher)
			if err != nil {
				if *r.Isdebug && err != io.EOF && !strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "reset") {
					log.Println("SERVER: 从LOCAL读数据错误！, ", err.Error())
				}
				break
			}
			//每次写之前更新一下写超时的判定时间点
			r.tcptotarget.SetWriteDeadline(time.Now().Add(time.Duration(*r.TcpWriteTimeout) * time.Second))
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
		//每次读操作前更新一下读超时的时间点
		r.tcptotarget.SetReadDeadline(time.Now().Add(time.Duration(*r.TcpReadTimeout) * time.Second))
		if ln, err = r.tcptotarget.Read(buf); err != nil {
			if *r.Isdebug && err != io.EOF && !strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "reset") {
				log.Println("SERVER 从TARGET读数据错误！, ", err.Error())
			}
			break
		} else {
			targettoserver = targettoserver + ln
			//每次写前更新一下写超时的判定时间点
			r.connfromclient.SetWriteDeadline(time.Now().Add(time.Duration(*r.TcpWriteTimeout) * time.Second))
			_, err = mycrypto.EncryptTo(buf[:ln], r.connfromclient, *r.keybyte, r.nonce, []byte{0xfc, 0xff}, r.processcipher)
			if err != nil {
				if *r.Isdebug {
					log.Printf("SERVER 返回来自TARGET的TCP数据失败！ %s\n", err.Error())
				}
				break
			}
		}
	}
	//防止后面close后这个变量消失，这里新建一个变量存着Target的地址数据
	TCPTOaddr := r.tcptotarget.RemoteAddr().String()
	clink := r.connfromclient.RemoteAddr().String()
	r.Close()
	fmt.Printf("SERVER: TCP CONNECT [%s]->[SERVER]->[%s] SEND:%s RECV:%s\n", clink, TCPTOaddr, pubpro.ReadableBytes(<-servertotarget), pubpro.ReadableBytes(targettoserver))
	return true
}

//接管处理UDP请求
func (r *processer) processudp() bool {
	defer r.Close()
	var err1 error
	//laddr为nil时,监听所有地址和随机选择可用端口
	r.udptotarget, err1 = net.ListenUDP("udp", nil)
	if err1 != nil {
		log.Println("SERVER UDP端口监听启动失败！ , ", err1.Error())
		return false
	}
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
			//更新UDP的最大读写超时判定时间点
			r.udptotarget.SetReadDeadline(time.Now().Add(time.Second * time.Duration(*r.UdpLifeTime)))
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
			//更新一下写超时的判定时间点
			r.connfromclient.SetWriteDeadline(time.Now().Add(time.Duration(*r.TcpWriteTimeout) * time.Second))
			//通过命令连接送回UDP数据包
			_, err2 := mycrypto.EncryptTo(append(writebuf, buf[:rcn]...), r.connfromclient, *r.keybyte, r.nonce, []byte{0xfc, 0xff}, r.processcipher)
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
		r.connfromclient.SetReadDeadline(time.Now().Add(time.Second * time.Duration(*r.TcpReadTimeout)))
		fromlocaldata, err1 = mycrypto.DecryptFrom(r.connfromclient, *r.keybyte, r.nonce, []byte{0xff, 0xff}, r.processcipher)
		if err1 != nil {
			if *r.Isdebug {
				log.Println("SERVER UoT隧道读数据失败 , ", err1.Error())
			}
			break
		}
		if len(fromlocaldata) < 5 {
			fmt.Printf("SERVER 来自LOCAL的过短UDP数据包 |%x|\n", fromlocaldata)
			return false
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
		r.udptotarget.SetWriteDeadline(time.Now().Add(time.Duration(*r.UdpLifeTime) * time.Second))
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
	clink := r.connfromclient.RemoteAddr().String()
	r.Close()
	fmt.Printf("SERVER: UDP ASSOCIATE [%s]->[SERVER]->[?] SEND:%s RECV:%s\n ", clink, pubpro.ReadableBytes(servertotargetudp), pubpro.ReadableBytes(<-targettoserverudp))
	return true
}
