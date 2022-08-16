package pubpro

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
)

var isdebug bool = false

func SetDebug(mode bool) {
	isdebug = mode
}

func IntToBytes(n int) []byte {
	data := int32(n)
	bytebuf := bytes.NewBuffer([]byte{})
	binary.Write(bytebuf, binary.BigEndian, data)
	return bytebuf.Bytes()
}

func BytesToInt(bys []byte) int {
	bytebuff := bytes.NewBuffer(bys)
	var data int32
	binary.Read(bytebuff, binary.BigEndian, &data)
	return int(data)
}

func UInt16ToBytes(n uint16) []byte {
	bytebuf := bytes.NewBuffer([]byte{})
	binary.Write(bytebuf, binary.BigEndian, n)
	return bytebuf.Bytes()
}

func BytesTouInt16(bys []byte) int {
	return int(binary.BigEndian.Uint16(bys))
}

func ReadableBytes(rb int) string {
	if rb < 1024 {
		return fmt.Sprint(rb, "B")
	}
	rb2 := float32(rb * 1.0000 / 1024)
	if rb2 < 1024 {
		return fmt.Sprintf("%.01fKB", rb2)
	}
	rb2 = rb2 / 1024
	if rb2 < 1024 {
		return fmt.Sprintf("%.02fMB", rb2)
	}
	rb2 = rb2 / 1024
	if rb2 < 1024 {
		return fmt.Sprintf("%.03fGB", rb2)
	}
	rb2 = rb2 / 1024
	if rb2 < 1024 {
		return fmt.Sprintf("%.06fTB", rb2)
	}
	return "0B"
}

func ConnectBytes(byte1 []byte, byte2 []byte) []byte {
	return append(byte1, byte2[:]...)
}

func ReadbytesFrom(conn net.Conn, bytesize int64) ([]byte, error) {
	return ioutil.ReadAll(io.LimitReader(conn, bytesize))
}

func GetOutBoundIP(targetip string) net.IP {
	conn, err := net.Dial("udp", targetip)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return conn.LocalAddr().(*net.UDPAddr).IP
}

func BytesToTcpAddr(netbyte []byte) net.TCPAddr {
	var RTAddr net.TCPAddr
	n := len(netbyte)
	// netbyte 代表请求的远程服务器地址类型，值长度1个字节，有三种类型
	switch netbyte[0] {
	case 0x01:
		//	IP V4 address: X'01'
		RTAddr.IP = netbyte[1 : 1+net.IPv4len]
	case 0x03:
		//	DOMAINNAME: X'03'
		ipAddr, err := net.ResolveIPAddr("ip", string(netbyte[2:n-2]))
		if err != nil {
			if isdebug {
				log.Println("网址", string(netbyte[2:n-2]), "转IP发生错误 , ", err.Error())
			}
			return RTAddr
		}
		RTAddr.IP = ipAddr.IP
	case 0x04:
		//	IP V6 address: X'04'
		RTAddr.IP = netbyte[1 : 1+net.IPv6len]
	default:
		log.Printf("无法识别的地址类型数据 , %x \n", netbyte)
		return RTAddr
	}
	RTAddr.Port = BytesTouInt16(netbyte[n-2 : n])
	return RTAddr
}

func AddrToBytes(ip net.IP, toport int) []byte {
	var res []byte
	if ip = ip.To4(); ip != nil {
		//IPv4, len is 4
		res = append([]byte{0x01}, ip...)
	} else {
		//IPv6, len is 16
		res = append([]byte{0x04}, ip...)
	}
	return append(res, UInt16ToBytes(uint16((toport)))...)
}
