package pubpro

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"time"
)

func Int32ToBytes(inn int32) []byte {
	bytebuf := bytes.NewBuffer([]byte{})
	binary.Write(bytebuf, binary.BigEndian, inn)
	return bytebuf.Bytes()
}

func BytesToInt32(bys []byte) int32 {
	bytebuff := bytes.NewBuffer(bys)
	var data int32
	binary.Read(bytebuff, binary.BigEndian, &data)
	return data
}

func Int64toBytes(innum int64) []byte {
	bytebuf := bytes.NewBuffer([]byte{})
	binary.Write(bytebuf, binary.BigEndian, innum)
	return bytebuf.Bytes()
}

func BytesToInt64(indata []byte) int64 {
	bytebuff := bytes.NewBuffer(indata)
	var data int64
	binary.Read(bytebuff, binary.BigEndian, &data)
	return data
}

func MD5toBytes(indata []byte) []byte {
	md5bytes := make([]byte, 0, 16)
	md5data := md5.Sum(indata)
	for i := 0; i < 16; i++ {
		md5bytes = append(md5bytes, md5data[i])
	}
	return md5bytes
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
	rb2 := float32(rb / 1024)
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

func BytesToTcpAddr(netbyte []byte) *net.TCPAddr {
	var RTAddr *net.TCPAddr = &net.TCPAddr{}
	if len(netbyte) < 5 {
		return nil
	}
	switch netbyte[0] {
	case 0x01:
		if len(netbyte) != 7 {
			return nil
		}
		RTAddr.IP = netbyte[1:5]
		RTAddr.Port = BytesTouInt16(netbyte[5:7])
	case 0x03:
		//	DOMAINNAME: X'03'
		var err error
		RTAddr, err = net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", netbyte[2:2+int(netbyte[1])], BytesTouInt16(netbyte[2+int(netbyte[1]):2+int(netbyte[1])+2])))
		if err != nil {
			return nil
		}
	case 0x04:
		//	IP V6 address: X'04'
		if len(netbyte) != 19 {
			return nil
		}
		RTAddr.IP = netbyte[1:17]
		RTAddr.Port = BytesTouInt16(netbyte[17:19])
	default:
		return nil
	}
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

type Queue struct {
	first     *node
	last      *node
	n         int
	writelock sync.Mutex
}

type node struct {
	nonce    []byte
	timenode int64
	Next     *node
}

//新建一个FIFO链表
func NewQueue() Queue {
	return Queue{}
}

//检查队列是否为空
func (q *Queue) IsEmpty() bool {
	return q.n == 0
}

//返回队列元素数量
func (q *Queue) Size() int {
	return q.n
}

//添加一个对象，自动为这个对象添加时间戳
func (q *Queue) Add(nonce []byte) {
	defer q.writelock.Unlock()
	q.writelock.Lock()
	oldlast := q.last
	q.last = &node{}
	q.last.nonce = nonce
	q.last.timenode = time.Now().Unix()
	q.last.Next = nil
	if q.IsEmpty() {
		q.first = q.last
	} else {
		oldlast.Next = q.last
	}
	q.n++
}

//返回删除后队列里剩余的对象数量
func (q *Queue) Del() int {
	defer q.writelock.Unlock()
	q.writelock.Lock()
	if q.IsEmpty() {
		return 0
	}
	q.first = q.first.Next
	if q.IsEmpty() {
		q.last = nil
	}
	q.n--
	return q.n
}

func (q *Queue) Exist(nownonce []byte) bool {
	if q.IsEmpty() {
		return false
	}
	nowitem := q.first
	for {
		if bytes.Equal(nownonce, nowitem.nonce) {
			return true
		}
		if nowitem.Next == nil {
			return false
		}
		nowitem = nowitem.Next
	}
}

func (q *Queue) GetFirst() (*[]byte, *int64) {
	if q.IsEmpty() {
		return nil, nil
	}
	return &q.first.nonce, &q.first.timenode
}

func (q *Queue) GetLast() (*[]byte, *int64) {
	if q.IsEmpty() {
		return nil, nil
	}
	return &q.last.nonce, &q.first.timenode
}
