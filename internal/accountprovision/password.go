package accountprovision

import (
	"crypto/rand"
	"math/big"
	"runtime"
)

const PasswordBytes = 32

var passwordClasses = [][]byte{
	[]byte("ABCDEFGHJKLMNPQRSTUVWXYZ"),
	[]byte("abcdefghijkmnopqrstuvwxyz"),
	[]byte("23456789"),
	[]byte("!#$%&*+-=?@^_"),
}

type CryptoPasswordGenerator struct{}

func (CryptoPasswordGenerator) Generate() ([]byte, error) {
	password := make([]byte, PasswordBytes)
	all := make([]byte, 0, 80)
	for index, class := range passwordClasses {
		value, err := randomByte(class)
		if err != nil {
			zeroBytes(password)
			return nil, provisionError("password-random-failed")
		}
		password[index] = value
		all = append(all, class...)
	}
	for index := len(passwordClasses); index < len(password); index++ {
		value, err := randomByte(all)
		if err != nil {
			zeroBytes(password)
			return nil, provisionError("password-random-failed")
		}
		password[index] = value
	}
	for index := len(password) - 1; index > 0; index-- {
		selection, err := rand.Int(rand.Reader, big.NewInt(int64(index+1)))
		if err != nil {
			zeroBytes(password)
			return nil, provisionError("password-random-failed")
		}
		other := int(selection.Int64())
		password[index], password[other] = password[other], password[index]
	}
	return password, nil
}

func randomByte(alphabet []byte) (byte, error) {
	selection, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
	if err != nil {
		return 0, err
	}
	return alphabet[selection.Int64()], nil
}

//go:noinline
func zeroBytes(buffer []byte) {
	for index := range buffer {
		buffer[index] = 0
	}
	runtime.KeepAlive(buffer)
}
