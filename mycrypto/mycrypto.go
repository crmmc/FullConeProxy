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
	"io"
	"log"
	"net"

	"../pubpro"
)

var isdebug bool = true

func SetDebug(mode bool) {
	isdebug = mode
}

func Strtokey128(str string) ([]byte, error) {
	return hex.DecodeString(fmt.Sprintf("%x", md5.Sum([]byte(str))))
}

func Strtokey256(str string) ([]byte, error) {
	bytes, err := Strtokey128(str)
	return pubpro.ConnectBytes(bytes, bytes), err
}

func Makenonce() []byte {
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Println("创建Nonce出现错误, ", err.Error())
		return nil
	}
	return nonce
}

func DecryptFrom(sconn net.Conn, key []byte, nownonce []byte) ([]byte, error) {

	n, err := pubpro.ReadbytesFrom(sconn, 4)
	if err != nil {
		if isdebug {
			log.Println("数据接收模块发现无法识别的包大小! , ", err.Error())
		}
		return nil, err
	}
	datasize := pubpro.BytesToInt(n)
	enddata, errr := pubpro.ReadbytesFrom(sconn, int64(datasize))
	if errr != nil {
		if isdebug {
			log.Println("数据接收模块发现错误! , ", errr.Error())
		}
		return nil, err
	}
	return DecodeAesGCM(enddata, key, nownonce)
}

func EncryptTo(data []byte, ento net.Conn, key []byte, nownonce []byte) (int, error) {
	enddata, err := EncodeAesGCM(data, key, nownonce)
	if err != nil {
		if isdebug {
			log.Println("加密数据失败!, ", err.Error())
		}
		return 0, err
	}
	datasize := pubpro.IntToBytes(len(enddata))
	n, errw := ento.Write(pubpro.ConnectBytes(datasize, enddata))
	if errw != nil {
		if isdebug {
			log.Println("发送数据出现错误!, ", errw.Error())
		}
		return 0, errw
	}
	return n, nil
}

//加密过程：
//  1、处理数据，对数据进行填充，采用PKCS7（当密钥长度不够时，缺几位补几个几）的方式。
//  2、对数据进行加密，采用AES加密方法中CBC加密模式
//  3、对得到的加密数据，进行base64加密，得到字符串
// 解密过程相反

//16,24,32位字符串的话，分别对应AES-128，AES-192，AES-256 加密方法
//key不能泄露

//pkcs7Padding 填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	//判断缺少几位长度。最少1，最多 blockSize
	padding := blockSize - len(data)%blockSize
	//补足位数。把切片[]byte{byte(padding)}复制padding个
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

//pkcs7UnPadding 填充的反向操作
func pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("加密字符串错误！")
	}
	//获取填充的个数
	unPadding := int(data[length-1])
	return data[:(length - unPadding)], nil
}

//AesEncryptCBC 加密
func AesEncryptCBC(data []byte, key []byte) ([]byte, error) {
	//创建加密实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//判断加密快的大小
	blockSize := block.BlockSize()
	//填充
	encryptBytes := pkcs7Padding(data, blockSize)
	//初始化加密数据接收切片
	crypted := make([]byte, len(encryptBytes))
	//使用cbc加密模式
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	//执行加密
	blockMode.CryptBlocks(crypted, encryptBytes)
	return crypted, nil
}

//AesDecryptCBC 解密
func AesDecryptCBC(data []byte, key []byte) ([]byte, error) {
	//创建实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//获取块的大小
	blockSize := block.BlockSize()
	//使用cbc
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	//初始化解密数据接收切片
	crypted := make([]byte, len(data))
	//执行解密
	blockMode.CryptBlocks(crypted, data)
	//去除填充
	crypted, err = pkcs7UnPadding(crypted)
	if err != nil {
		return nil, err
	}
	return crypted, nil
}

//AES GCM加密
func EncodeAesGCM(data []byte, key []byte, adddata []byte) ([]byte, error) {
	ivsize := 16
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte(""), err
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, ivsize)
	if err != nil {
		return []byte(""), err
	}
	iv := make([]byte, ivsize)                                               // NonceSize=16
	rand.Read(iv)                                                            //获取随机值
	return pubpro.ConnectBytes(iv, aesgcm.Seal(nil, iv, data, adddata)), nil //加密,密文为:iv+密文+tag
}

func DecodeAesGCM(enddata []byte, key []byte, adddata []byte) ([]byte, error) {
	ivsize := 16                     //nonceSize,tag的长度，用于open时候生成tag,默认12
	block, err := aes.NewCipher(key) //生成加解密用的block
	if err != nil {
		return []byte(""), err
	}
	//根据不同加密算法，也有不同tag长度的方法设定和调用，比如NewGCMWithTagSize、newGCMWithNonceAndTagSize
	aesgcm, err := cipher.NewGCMWithNonceSize(block, ivsize)
	if err != nil {
		return []byte(""), err
	}
	if len(enddata) <= aesgcm.NonceSize() { // 长度应该>iv
		return []byte(""), errors.New("AES数据太短！解密失败") //解密失败
	}
	iv := enddata[:aesgcm.NonceSize()]     //分离出IV
	enddata = enddata[aesgcm.NonceSize():] // 密文,tag是调用open方法时候通过密文和前面new时候传的size来进行截取的
	deddata, err := aesgcm.Open(nil, iv, enddata, adddata)
	return deddata, err
}
