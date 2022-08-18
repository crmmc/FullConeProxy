package mycrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"runtime"
	"time"

	"../pubpro"
	gzip "github.com/klauspost/pgzip"
)

var isdebug bool = true
var isongzip bool = false
var maxallowtimeerror int64 = 10 //最大允许收发数据包的两端时间相差10秒

func SetDebug(mode bool) {
	isdebug = mode
}
func SetGzip(mode bool) {
	isongzip = mode
}

func Strtokey128(str string) ([]byte, error) {
	return hex.DecodeString(fmt.Sprintf("%x", md5.Sum([]byte(str))))
}

func Strtokey256(str string) ([]byte, error) {
	bytes, err := Strtokey128(str)
	return pubpro.ConnectBytes(bytes, bytes), err
}

func Makenonce() ([]byte, error) {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	return nonce, err
}

func DecryptFrom(sconn net.Conn, key []byte, nownonce []byte) ([]byte, error) {
	numsizebyte, err := pubpro.ReadbytesFrom(sconn, 4)
	if err != nil {
		if isdebug {
			log.Println("数据接收模块发现无法识别的包大小! , ", err.Error())
		}
		return nil, err
	}
	datasize := int64(pubpro.BytesToInt32(numsizebyte))
	var enddata []byte
	enddata, err = pubpro.ReadbytesFrom(sconn, datasize)
	if err != nil {
		return nil, err
	}
	//时间戳与KEY一起HASH得到附加数据，参考v2的想法
	if nownonce == nil {
		datasize = time.Now().Unix()
		var ddata []byte
		for tmpsize := maxallowtimeerror * int64(-1); tmpsize < maxallowtimeerror; tmpsize++ {
			nownonce = pubpro.MD5toBytes(pubpro.ConnectBytes(key, pubpro.Int64toBytes(datasize+tmpsize)))
			ddata, err = DecodeAesGCM(enddata, key, nownonce)
			if err == nil {
				return ddata, nil
			}
		}
	} else {
		enddata, err = DecodeAesGCM(enddata, key, nownonce)
	}
	return enddata, err
}

func EncryptTo(data []byte, ento net.Conn, key []byte, nownonce []byte) (int, error) {
	if nownonce == nil {
		nownonce = pubpro.MD5toBytes(pubpro.ConnectBytes(key, pubpro.Int64toBytes(time.Now().Unix())))
	}
	enddata, err := EncodeAesGCM(data, key, nownonce)
	if err != nil {
		return 0, err
	}
	datasize := pubpro.Int32ToBytes(int32(len(enddata)))
	var n int
	n, err = ento.Write(pubpro.ConnectBytes(datasize, enddata))
	if err != nil {
		return 0, err
	}
	return n, nil
}

//AES GCM加密
func EncodeAesGCM(data []byte, key []byte, adddata []byte) ([]byte, error) {
	if isongzip {
		data = GZcompress(data)
		if data == nil {
			return nil, errors.New("EncodeAesGCM Gzip压缩数据失败")
		}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("EncodeAesGCM 新建AES加密器失败" + err.Error())
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, errors.New("EncodeAesGCM 设置AES加密器IV Size失败" + err.Error())
	}
	var iv []byte
	iv, err = Makenonce() //获取16位随机值
	if err != nil {
		return nil, errors.New("EncodeAesGCM 获取随机数据失败！" + err.Error())
	}
	return pubpro.ConnectBytes(iv, aesgcm.Seal(nil, iv, data, adddata)), nil //加密并合并加密数据，得到iv+data
}

func DecodeAesGCM(enddata []byte, key []byte, adddata []byte) ([]byte, error) {
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
	if len(enddata) <= aesgcm.NonceSize() { // 长度应该>iv
		return nil, errors.New("AES数据太短！解密失败") //解密失败
	}
	var dedata []byte
	//得到的密文格式是 iv + playload，所以分别传入IV,data，再加上add data就可以解密里
	dedata, err = aesgcm.Open(nil, enddata[:aesgcm.NonceSize()], enddata[aesgcm.NonceSize():], adddata)
	if err != nil {
		return nil, errors.New("DecodeAesGCM 解密AES数据出错! " + err.Error())
	}
	if isongzip {
		dedata = GZdecompress(dedata)
		if dedata == nil {
			return nil, errors.New("DecodeAesGCM 解压缩Gzip数据出错! ")
		}
	}
	return dedata, err
}

func GZcompress(indata []byte) []byte {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	//设置第三库的分块压缩门限和最大并行压缩数
	gz.SetConcurrency(4096, runtime.GOMAXPROCS(0))
	if _, err := gz.Write(indata); err != nil {
		return nil
	}
	if err := gz.Flush(); err != nil {
		return nil
	}
	if err := gz.Close(); err != nil {
		return nil
	}
	return b.Bytes()
}

func GZdecompress(indata []byte) []byte {
	rdata := bytes.NewReader(indata)
	gz, err := gzip.NewReader(rdata)
	if err != nil {
		return nil
	}
	var buf bytes.Buffer
	// 从 Reader 中读取出数据
	if _, err := buf.ReadFrom(gz); err != nil {
		return nil
	}
	return buf.Bytes()
}
