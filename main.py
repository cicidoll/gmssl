from EllipticCurve import SM2EllipticCurve
from PointCalculate import PointCalculate
from pysmx.SM3 import hash_msg
from functools import reduce
from typing import List, Tuple
import random, math, binascii

class SM2Encrypt:
    """ 
    本类只计算04非压缩公钥
    SM2加密数据使用公钥(x,y)进行加密，加密结果为c1c3c2
        c1:随机数k与基点G(x,y)的多倍点运算，结果记为点(kx, ky)
        c2:实际密文值
        c3:使用SM3对于 kx||data||ky 的hash值，在解密时校验解密结果是否正确
    """
    # 椭圆曲线方程参数
    elliptic_curve: SM2EllipticCurve
    # 倍点计算类
    point_calculate: PointCalculate
    # 提取的公钥PB
    PB: List[int]
    # k是随机数，取值范围为[1,n-1]，n是椭圆曲线子群的阶 整数类型
    k: int
    # 输出密文C=C1||C3||C2,  C1和C3的长度是固定的，，C3是32字节，很方便C从中提取C1，C3和C2
    # c1计算值 c1是65字节 PC||x1||y1,其中PC为单一字节且PC=04 hex格式

    def __init__(self, sm2_public_key: str) -> None:
        """ 计算前实例化各类参数
            plain_text为十六进制
        """
        # 载入椭圆曲线方程曲线
        self.elliptic_curve = SM2EllipticCurve()
        # 初始化倍点计算类
        self.point_calculate = PointCalculate(self.elliptic_curve)
        # 提取公钥信息
        self.PB = self._extract_public_key(sm2_public_key)

    def main(self, plain_text: str):
        """ 加密主线程 """
        # 初始化A5的结果t为0
        t = "0"
        while int(t, 16) == 0:
            # A1流程：产生随机数k
            self.k: int = random.randint(1, self.elliptic_curve.n-1)
            # A2流程：计算C1 hex格式 补齐64位
            C1 = '04%s' % ((reduce(lambda x,y: '%s%s' % (hex(x).replace('0x', '').zfill(64), hex(y).replace('0x', '').zfill(64)),self._encrypt_c1())))
            # A4流程：计算x2, y2十六进制, x2||y2
            x2, y2 = self._encrypt_A4()
            hex_x2_and_y2: str = x2 + y2
            # A5流程：计算t t=KDF(x2||y2,Mlen)
            # KDF是密钥派生函数 设发送的消息为比特串M，klen为M的比特长度。十六进制
            t = self.sm3_kdf(hex_x2_and_y2.encode('utf8'), len(plain_text)/2)
        # A6流程：计算C2: 异或
        form = '%%0%dx' % len(plain_text)
        C2 = form % (int(plain_text, 16) ^ int(t, 16))
        C3 = self._hash([
            i for i in bytes.fromhex('%s%s%s'% (x2, plain_text, y2))
        ])
        return bytes.fromhex('%s%s%s' % (C1, C2, C3))

    def _encrypt_c1(self) -> List[int]:
        """ 计算c1
            c1 = 随机数k*椭圆曲线基点G(倍点运算)
        """
        result = self.point_calculate.muly_point(
            self.k,
            self.elliptic_curve.G
        )
        return result

    def _encrypt_A4(self) -> Tuple(str, str):
        """ 计算A4
            return为十六进制x2||y2
        """
        # kPB = k*PB k为随机数，PB为公钥
        kPB: List[int] = self.point_calculate.muly_point(
            self.k,
            [int(self.PB[0], 16), int(self.PB[1], 16)]
        )
        # 转换为十六进制
        hex_kPB: List[str] = list(map(lambda x: hex(x)[2:], kPB))
        return (hex_kPB[0], hex_kPB[1])
        
    def _extract_public_key(self, sm2_public_key: str) -> List[int]:
        """ 提取公钥x, y
            仅处理04类型公钥，以16进制返回
        """
        if sm2_public_key[0:2] != "04": return None
        return [sm2_public_key[2:66], sm2_public_key[66:]]

    def sm3_kdf(self, z: bytes, klen: int): # z为16进制表示的比特串（str），klen为密钥长度（单位byte）
        klen = int(klen)
        ct = 0x00000001
        rcnt = math.ceil(klen/32)
        zin = [i for i in bytes.fromhex(z.decode('utf8'))]
        ha = ""
        for i in range(rcnt):
            msg = zin  + [i for i in binascii.a2b_hex(('%08x' % ct).encode('utf8'))]
            ha = ha + self._hash(msg)
            ct += 1
        return ha[0: klen * 2]

    def _hash(self, input_str: str) -> str:
        """ SM3哈希函数
            :return hex格式字符串
        """
        return hash_msg(input_str)