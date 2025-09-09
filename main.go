package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
	blst "github.com/supranational/blst/bindings/go"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const salt = "BLS-SIG-KEYGEN-SALT-"

var hardenedOffset uint32 = 0x80000000

func hkdfModR(ikm []byte, info []byte) []byte {
	h := hkdf.New(sha256.New, ikm, []byte(salt), info)
	okm := make([]byte, 48)
	if _, err := io.ReadFull(h, okm); err != nil {
		log.Fatalf("HKDF failed: %v", err)
	}
	return okm
}

func deriveMasterSK(seed []byte) []byte {
	return hkdfModR(seed, nil)
}

func deriveChildSK(parentSK []byte, index uint32) []byte {
	data := append([]byte{0x00}, parentSK...)
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, index)
	data = append(data, indexBytes...)
	return hkdfModR(data, []byte("BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"))
}

func deriveBLSKeyEIP2333(seed []byte) {
	path := []uint32{
		12381 + hardenedOffset,
		3600 + hardenedOffset,
		0 + hardenedOffset,
		0 + hardenedOffset,
		0 + hardenedOffset,
	}

	skBytes := deriveMasterSK(seed)
	for _, index := range path {
		skBytes = deriveChildSK(skBytes, index)
	}

	sk := blst.KeyGen(skBytes)
	pk := new(blst.P1Affine).From(sk)

	msg := []byte("hello world")
	sig := new(blst.P2Affine).Sign(sk, msg, []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"))

	fmt.Printf("[BLS/EIP-2333] Private Key : 0x%s\n", hex.EncodeToString(sk.Serialize()))
	fmt.Printf("[BLS/EIP-2333] Public Key  : 0x%s\n", hex.EncodeToString(pk.Serialize()))
	fmt.Printf("[BLS/EIP-2333] Signature   : 0x%s\n", hex.EncodeToString(sig.Compress()))
}

func publicKeyToAddress(compressedPubKey []byte) string {
	pubKeyECDSA, err := crypto.DecompressPubkey(compressedPubKey)
	if err != nil {
		log.Fatalf("Failed to decompress ECDSA public key: %v", err)
	}
	uncompressed := crypto.FromECDSAPub(pubKeyECDSA)
	hash := sha3.NewLegacyKeccak256()
	hash.Write(uncompressed[1:])
	addr := hash.Sum(nil)[12:]
	return "0x" + hex.EncodeToString(addr)
}

func deriveECDSAKey(seed []byte) {
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		log.Fatalf("Failed to generate master key: %v", err)
	}

	purpose, err := masterKey.NewChildKey(bip32.FirstHardenedChild + 44)
	if err != nil {
		log.Fatalf("Failed to derive purpose: %v", err)
	}
	coinType, err := purpose.NewChildKey(bip32.FirstHardenedChild + 60)
	if err != nil {
		log.Fatalf("Failed to derive coinType: %v", err)
	}
	account, err := coinType.NewChildKey(bip32.FirstHardenedChild + 0)
	if err != nil {
		log.Fatalf("Failed to derive account: %v", err)
	}
	change, err := account.NewChildKey(0)
	if err != nil {
		log.Fatalf("Failed to derive change: %v", err)
	}
	addressIndex, err := change.NewChildKey(0)
	if err != nil {
		log.Fatalf("Failed to derive address index: %v", err)
	}

	privKey := addressIndex.Key
	pubKey := addressIndex.PublicKey().Key

	fmt.Println("[ECDSA] Private Key:", hex.EncodeToString(privKey))
	fmt.Println("[ECDSA] Public Key :", hex.EncodeToString(pubKey))
	fmt.Println("[ECDSA] Address from Public Key:", publicKeyToAddress(pubKey))
}

func main() {
	var mnemonic string

	if len(os.Args) > 0 {
		mnemonic = os.Args[1]
	}

	if mnemonic == "" {
		entropy, err := bip39.NewEntropy(256) // 24-word mnemonic
		mnemonic, err = bip39.NewMnemonic(entropy)
		if err != nil {
			log.Fatalf("Failed to generate mnemonic: %v", err)
		}
	}

	fmt.Println("Mnemonic:", mnemonic)

	if !bip39.IsMnemonicValid(mnemonic) {
		log.Fatal("Invalid mnemonic")
	}

	seed := bip39.NewSeed(mnemonic, "")

	fmt.Println("\n===== ECDSA Key Derivation (m/44'/60'/0'/0/0) =====")
	deriveECDSAKey(seed)

	fmt.Println("\n===== BLS Key Derivation (EIP-2333 + EIP-2334) =====")
	deriveBLSKeyEIP2333(seed)
}
