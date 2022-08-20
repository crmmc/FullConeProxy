package mycrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"../pubpro"
)

var isdebug bool = true
var maxallowtimeerror int64 = 10 //最大允许收发数据包的两端时间相差10秒
var timeiv int64 = -404          //时间戳的偏移量，防止被记录包发送时间后用密码解出包的内容，其实这一点应该随机生成更好

func SetDebug(mode bool) {
	isdebug = mode
}

//设置时间戳的偏移量
func SetTimestmpDelay(delay int64) {
	timeiv = delay
}

func SetMaxAllowTimeError(settime int64) {
	maxallowtimeerror = settime
}

func Strtokey128(str string) ([]byte, error) {
	return hex.DecodeString(fmt.Sprintf("%x", md5.Sum([]byte(str))))
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
func DecryptFrom(sconn net.Conn, key []byte, iv []byte, adddata []byte) ([]byte, error) {
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
			ddata, err = DecodeAesGCM(enddata, key, iv, adddata)
			if err == nil {
				//去掉填充用的随机数据
				return ddata[uint8(ddata[0])+1:], nil
			}
		}
	} else {
		enddata, err = DecodeAesGCM(enddata, key, iv, adddata)
		if err == nil {
			//去掉填充用的随机数据
			return enddata[uint8(enddata[0])+1:], nil
		}
	}
	return nil, errors.New("来自[" + sconn.RemoteAddr().String() + "]的加密数据解密失败，可能是错误的密码，不同步的系统时间，亦或是正在遭到主动探测攻击导致的错误发生 " + err.Error())
}

func EncryptTo(data []byte, ento net.Conn, key []byte, iv []byte, adddata []byte) (int, error) {
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
	randombyte := make([]byte, uint8(randomdatasizebyte[0]))
	_, err = rand.Read(randombyte)
	if err != nil {
		if isdebug {
			log.Println("无法生成随机数据 , ", err.Error())
		}
		return 0, err
	}
	var enddata []byte
	data = append(append(randomdatasizebyte, randombyte...), data...)
	enddata, err = EncodeAesGCM(data, key, iv, adddata)
	if err != nil {
		return 0, err
	}
	var n int
	n, err = ento.Write(append(pubpro.Int32ToBytes(int32(len(enddata))), enddata...))
	return n, err
}

//AES GCM加密
func EncodeAesGCM(data []byte, key []byte, iv []byte, adddata []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("EncodeAesGCM 新建AES加密器失败" + err.Error())
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, errors.New("EncodeAesGCM 设置AES加密器IV Size失败" + err.Error())
	}
	return aesgcm.Seal(nil, iv, data, adddata), nil //得到data
}

func DecodeAesGCM(enddata []byte, key []byte, iv []byte, adddata []byte) ([]byte, error) {
	block, err := aes.NewCipher(key) //生成加解密用的block
	if err != nil {
		return nil, errors.New("DecodeAesGCM 新建AES对象失败" + err.Error())
	}
	//根据不同加密算法，也有不同tag长度的方法设定和调用，比如NewGCMWithTagSize、newGCMWithNonceAndTagSize
	var aesgcm cipher.AEAD
	aesgcm, err = cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}
	var dedata []byte
	dedata, err = aesgcm.Open(nil, iv, enddata, adddata)
	if err != nil {
		return nil, errors.New("DecodeAesGCM 解密AES数据出错! " + err.Error())
	}
	return dedata, err
}
