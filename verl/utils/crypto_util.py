# -*- coding: utf-8 -*-
"""
Author  : chenli2
Time    : 2025/3/15 21:02
Desc    :
"""
import struct
from Crypto.Cipher import AES
import os
import argparse

try:
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    from Crypto.Util.py3compat import bchr, bord

    def pad(data_to_pad, block_size):
        """PKCS#7 填充实现"""
        padding_len = block_size - len(data_to_pad) % block_size
        padding = bchr(padding_len) * padding_len

        return data_to_pad + padding

    def unpad(padded_data, block_size):
        """去掉 PKCS#7 填充"""
        pdata_len = len(padded_data)
        if pdata_len % block_size:
            raise ValueError("Input data is not padded")
        padding_len = bord(padded_data[-1])
        if padding_len < 1 or padding_len > min(block_size, pdata_len):
            raise ValueError("Padding is incorrect.")
        if padded_data[-padding_len:] != bchr(padding_len) * padding_len:
            raise ValueError("PKCS#7 padding is incorrect.")

        return padded_data[:-padding_len]


def get_binary_content_from_file(in_filename, key, chunksize=64 * 1024):
    """用 AES-CBC 解密二进制文件字节串"""
    if isinstance(key, str):
        key = key.encode('utf-8')  # 转换为字节串

    chunk_per_file = b""
    with open(in_filename, 'rb') as infile:
        # 读走前 8 个字节的文件大小
        _ = struct.unpack('<Q', infile.read(8))[0]
        # 再读后 16 个字节的 iv
        iv = infile.read(16)
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        encrypted_filesize = os.path.getsize(in_filename)
        pos = 8 + 16  # the filesize and IV.

        while pos < encrypted_filesize:
            chunk = infile.read(chunksize)
            if len(chunk) % 16 != 0:
                chunk = pad(chunk, 16)
            pos += len(chunk)
            chunk = encryptor.decrypt(chunk)
            if pos == encrypted_filesize:
                chunk = unpad(chunk, AES.block_size)
            chunk_per_file += chunk

    assert isinstance(chunk_per_file, bytes)

    return chunk_per_file


def encrypt_file(key, file_path, chunksize=64 * 1024):
    """
    desc:
        使用 AES-CBC 加密 JSON 和 JSONL 文件，并在原文件名的主干部分添加 `_enc`，保留后缀
    param(s):
        - key (bytes): AES 加密密钥
        - file_path (str): 输入文件路径
    """
    out_file_path = f"{file_path}.enc"

    iv = os.urandom(16)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(file_path)

    with open(file_path, 'rb') as infile, open(out_file_path, 'wb') as outfile:
        outfile.write(struct.pack('<Q', filesize))
        outfile.write(iv)
        pos = 0
        while pos < filesize:
            chunk = infile.read(chunksize)
            pos += len(chunk)

            if pos == filesize:
                chunk = pad(chunk, AES.block_size)

            outfile.write(encryptor.encrypt(chunk))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('--file_path', required=True,
                        help='Path to encode.')
    parser.add_argument('--key', required=True,
                        help='密钥')

    args = parser.parse_args()

    encrypt_file(args.key, args.file_path)
