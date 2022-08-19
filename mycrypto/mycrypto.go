package mycrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"log"
	"net"
	"time"

	"../pubpro"
)

var isdebug bool = true
var maxallowtimeerror int64 = 10 //最大允许收发数据包的两端时间相差10秒
var timeiv int64 = -1956         //时间戳的偏移量，防止被记录包发送时间后用密码解出包的内容，其实这一点应该随机生成更好

func SetDebug(mode bool) {
	isdebug = mode
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
在加密数据前面加上随机填充的内容以混淆，随机填充内容随机长度（0-255），由数据包第一个字节决定，结构
 +--------------------+-------------+----------------+----------+---------+
 | Random data length | Random Data | payload length | playload |  CRC32  |
 +--------------------+-------------+----------------+----------+---------+
 |       1 byte       |   variable  |     4 byte     | variable |  4 byte |
 +--------------------+-------------+----------------+----------+---------+

*/

func DecryptFrom(sconn net.Conn, key []byte, nownonce []byte, adddata []byte) ([]byte, error) {
	randomsize := make([]byte, 1)
	_, err := sconn.Read(randomsize)
	if err != nil {
		return nil, errors.New("无法收到随机数据长度 , " + err.Error())
	}
	var randomdata []byte
	randomdata, err = pubpro.ReadbytesFrom(sconn, int64(uint8(randomsize[0])))
	if err != nil {
		return nil, errors.New("无法收到随机数据 , " + err.Error())
	}
	var numsizebyte []byte
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
	//首先校验包的完整性CRC32
	var packageCRC32 []byte
	packageCRC32, err = pubpro.ReadbytesFrom(sconn, 4)
	if err != nil {
		return nil, errors.New("无法收到包的CRC32")
	}
	//拼接已经接受到的数据 |randomsize|randomdata|numsizebyte|enddata|,计算CRC32
	nowCRC32num := crc32.ChecksumIEEE(append(randomsize, append(randomdata, append(numsizebyte, enddata...)...)...))
	if !bytes.Equal(packageCRC32, pubpro.Int32ToBytes(int32(nowCRC32num))) {
		return nil, errors.New("数据包CRC32校验不通过！可能正在遭受主动探测")
	}
	//时间戳与KEY一起HASH得到附加数据，参考v2的想法
	if nownonce == nil {
		//这里给获取的时间戳做一个独特的运算，防止密码被知道后，通过被记录的包发送时间运算出包的内容
		//偏移量改那个全局变量
		//借用前面的变量datasize储存timestmp
		datasize = time.Now().Unix() + timeiv
		var ddata []byte
		for tmpsize := maxallowtimeerror * int64(-1); tmpsize < maxallowtimeerror; tmpsize++ {
			nownonce = pubpro.MD5toBytes(append(key, pubpro.Int64toBytes(datasize+tmpsize)...))
			ddata, err = DecodeAesGCM(enddata, key, nownonce, adddata)
			if err == nil {
				return ddata, nil
			}
		}
	} else {
		enddata, err = DecodeAesGCM(enddata, key, nownonce, adddata)
	}
	return enddata, err
}

func EncryptTo(data []byte, ento net.Conn, key []byte, nownonce []byte, adddata []byte) (int, error) {
	if len(nownonce) != 16 {
		nownonce = pubpro.MD5toBytes(append(key, pubpro.Int64toBytes(time.Now().Unix()+timeiv)...))
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
	randombyte := make([]byte, uint8(randomdatasizebyte[0]))
	_, err = rand.Read(randombyte)
	if err != nil {
		if isdebug {
			log.Println("无法生成随机数据 , ", err.Error())
		}
		return 0, err
	}
	var enddata []byte
	enddata, err = EncodeAesGCM(data, key, nownonce, adddata)
	if err != nil {
		return 0, err
	}
	var n int
	gooddata := append(append(append(randomdatasizebyte, randombyte...), pubpro.Int32ToBytes(int32(len(enddata)))...), enddata...)
	//获得前面所有数据的CRC32
	nowCRC32 := crc32.ChecksumIEEE(gooddata)
	n, err = ento.Write(append(gooddata, pubpro.Int32ToBytes(int32(nowCRC32))...))
	if err != nil {
		return 0, err
	}
	return n, nil
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
	//得到的密文格式是data 通过初始IV可以解密
	dedata, err = aesgcm.Open(nil, iv, enddata, adddata)
	if err != nil {
		return nil, errors.New("DecodeAesGCM 解密AES数据出错! " + err.Error())
	}
	return dedata, err
}
