package mycrypto

import (
	"bytes"
	"compress/gzip"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log"
	"net"
	"time"

	"../pubpro"
)

var isdebug bool = true
var maxallowtimeerror int64 = 10 //最大允许收发数据包的两端时间相差10秒
var timeiv int64 = -404          //时间戳的偏移量，防止被记录包发送时间后用密码解出包的内容，其实这一点应该随机生成更好
var enablegzip bool = false      //是否开启压缩GZIP数据

func SetDebug(mode bool) {
	isdebug = mode
}

//是否开启GZIP压缩数据
func SetEnableGzip(mode bool) {
	enablegzip = mode
}

//设置时间戳的偏移量
func SetTimestmpDelay(delay int64) {
	timeiv = delay
}

func SetMaxAllowTimeError(settime int64) {
	maxallowtimeerror = settime
}

func Strtokey256(str string) ([]byte, error) {
	hash := sha256.New()
	hash.Write([]byte(str))
	return hash.Sum(nil), nil
}

func Makenonce() ([]byte, error) {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	return nonce, err
}

/*
加密数据后的结构
+----------------+-----------+
| payload length | playload  |
+----------------+-----------+
|     4 byte     | variable  |
+----------------+-----------+
+------------------+-----------+--------+
|Random Data length|Random Data|RealData|
+------------------+-----------+--------+
|       1 byte     | variable  |variable|
+------------------+-----------+--------+
*/

//如果被主动探测，遭到逐字节探测或被恶意修改的包重放，应该提示并记录内容，但是它发送的被修改的数据一定会解密失败
//但是与错误的版本和密码导致的数据解密失败分不开，这该如何是好，还是保持原来的反应吧

//用于接收私有协议加密数据的函数
func DecryptFrom(sconn net.Conn, key []byte, iv []byte, adddata []byte, aesadad cipher.AEAD) ([]byte, error) {
	var numsizebyte []byte
	var err error
	numsizebyte, err = pubpro.ReadbytesFrom(sconn, 4)
	if err != nil {
		return nil, errors.New("无法收到加密数据长度 " + err.Error())
	}
	datasize := int64(pubpro.BytesToInt32(numsizebyte))
	var enddata []byte
	enddata, err = pubpro.ReadbytesFrom(sconn, datasize)
	if err != nil {
		return nil, errors.New("无法收到加密数据 " + err.Error())
	}
	if len(iv) != 16 {
		//这里给获取的时间戳做一个独特的运算，防止密码被知道后，通过被记录的包发送时间运算出包的内容
		//偏移量改那个全局变量
		//借用前面的变量datasize储存timestmp
		datasize = time.Now().Unix() + timeiv
		var ddata []byte
		for tmpsize := maxallowtimeerror * int64(-1); tmpsize < maxallowtimeerror; tmpsize++ {
			iv = pubpro.MD5toBytes(append(key, pubpro.Int64toBytes(datasize+tmpsize)...))
			ddata, err = DecodeAesGCM(enddata, key, iv, adddata, aesadad)
			if err == nil {
				//去掉填充用的随机数据
				if enablegzip {
					//gzip只压缩了有效数据，所以在此解密
					return gzdecompress(ddata[uint8(ddata[0])+1:])
				} else {
					return ddata[uint8(ddata[0])+1:], nil
				}
			}
		}
	} else {
		enddata, err = DecodeAesGCM(enddata, key, iv, adddata, aesadad)
		if err == nil {
			//去掉填充用的随机数据
			if enablegzip {
				//gzip只压缩了有效数据，所以在此解密
				return gzdecompress(enddata[uint8(enddata[0])+1:])
			} else {
				return enddata[uint8(enddata[0])+1:], nil
			}
		}
	}
	return nil, errors.New("来自[" + sconn.RemoteAddr().String() + "]的加密数据解密失败，可能是错误的密码，不同步的系统时间，亦或是正在遭到主动探测攻击导致的错误发生 " + err.Error())
}

//用于发送私有协议加密数据的函数
func EncryptTo(data []byte, ento net.Conn, key []byte, iv []byte, adddata []byte, aesadad cipher.AEAD) (int, error) {
	if len(iv) != 16 {
		iv = pubpro.MD5toBytes(append(key, pubpro.Int64toBytes(time.Now().Unix()+timeiv)...))
	}
	randomdatasizebyte := make([]byte, 1)
	var err error
	_, err = rand.Read(randomdatasizebyte)
	if err != nil {
		if isdebug {
			log.Println("无法生成随机数据长度 , ", err.Error())
		}
		return 0, err
	}
	//防止填充数据太长了，浪费流量,最大生成的255，减两次准够
	if randomdatasizebyte[0] > 100 {
		randomdatasizebyte[0] = randomdatasizebyte[0] - 100
	}
	if randomdatasizebyte[0] > 100 {
		randomdatasizebyte[0] = randomdatasizebyte[0] - 100
	}
	if randomdatasizebyte[0] < 10 {
		randomdatasizebyte[0] = randomdatasizebyte[0] * 2
	}
	randombyte := make([]byte, uint8(randomdatasizebyte[0]))
	_, err = rand.Read(randombyte)
	if err != nil {
		if isdebug {
			log.Println("无法生成随机数据 , ", err.Error())
		}
		return 0, err
	}
	if enablegzip {
		//开启了GZIP压缩，只压缩data部分
		data, err = gzcompress(data)
		if err != nil {
			return 0, err
		}
	}
	var enddata []byte
	data = append(append(randomdatasizebyte, randombyte...), data...)
	enddata, err = EncodeAesGCM(data, key, iv, adddata, aesadad)
	if err != nil {
		return 0, err
	}
	var n int
	n, err = ento.Write(append(pubpro.Int32ToBytes(int32(len(enddata))), enddata...))
	return n, err
}

//AES GCM加密
func EncodeAesGCM(data []byte, key []byte, iv []byte, adddata []byte, aesgcm cipher.AEAD) ([]byte, error) {
	if aesgcm == nil {
		return nil, errors.New("DecodeAesGCM 无法使用的AEAD解密器")
	}
	return aesgcm.Seal(nil, iv, data, adddata), nil //得到data
}

func DecodeAesGCM(enddata []byte, key []byte, iv []byte, adddata []byte, aesgcm cipher.AEAD) ([]byte, error) {
	if aesgcm == nil {
		return nil, errors.New("DecodeAesGCM 无法使用的AEAD解密器")
	}
	var err error
	var dedata []byte

	dedata, err = aesgcm.Open(nil, iv, enddata, adddata)
	if err != nil {
		return nil, errors.New("DecodeAesGCM 解密AES数据出错! " + err.Error())
	}
	return dedata, err
}

func gzcompress(indata []byte) ([]byte, error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(indata); err != nil {
		return nil, errors.New("GZIP Compress Failed " + err.Error())
	}
	if err := gz.Flush(); err != nil {
		return nil, errors.New("GZIP Flush Failed " + err.Error())
	}
	if err := gz.Close(); err != nil {
		return nil, errors.New("GZIP Close Failed " + err.Error())
	}
	return b.Bytes(), nil
}

func gzdecompress(indata []byte) ([]byte, error) {
	rdata := bytes.NewReader(indata)
	gz, err := gzip.NewReader(rdata)
	if err != nil {
		return nil, errors.New("Decompress gzip data failed! " + err.Error())
	}
	var buf bytes.Buffer
	// 从 Reader 中读取出数据
	if _, err := buf.ReadFrom(gz); err != nil {
		return nil, errors.New("Read Data From gzip decompress buffer failed! " + err.Error())
	}
	return buf.Bytes(), nil
}
