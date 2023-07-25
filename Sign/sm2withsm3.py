from pysmx.SM3 import hash_msg
from SM2Key import calculate_public_key
from Calculate.EllipticCurve import SM2EllipticCurve
from Calculate.PointCalculate import PointCalculate, kG
from Calculate.ModCalculate import int_mod, decimal_mod
from typing import Tuple
import random

class SM2withSM3Sign:
    # 素数域256位椭圆曲线参数
    elliptic_curve = SM2EllipticCurve

    def __init__(self, private_key: str, public_key: str = "") -> None:
        # 赋值实例属性
        self.public_key = public_key if public_key != "" else calculate_public_key(private_key)
        self.private_key = private_key

    def sign(self, msg: str, userid: str = "1234567812345678") -> str:
        A2: int = int(self._A1andA2(msg, userid), base=16) # 十六进制
        R, S = self._A3A4A5A6(A2)
        return "%s%s" % (hex(R).replace("0x", "").zfill(64), hex(S).replace("0x", "").zfill(64))

    def _A1andA2(self, msg: str, userid: str) -> str:
        IDA: str = userid.encode('utf-8').hex() # userid 
        ENTLA: str = self.__hex_zfill(hex(int(len(IDA) / 2)*8)).zfill(4) # hex格式
        a, b, Gx, Gy = map(self.__hex_zfill, map(hex, (self.elliptic_curve.a, self.elliptic_curve.b, self.elliptic_curve._Gx, self.elliptic_curve._Gy)))
        ZA = self.__bytes_sm3((ENTLA+IDA+a+b+Gx+Gy+self.public_key).lower())
        M1 = ZA + self.__hex_zfill(msg.encode("utf-8").hex())
        A2 = self.__bytes_sm3(M1)
        return A2

    def _A3A4A5A6(self, A2: int) -> Tuple[int, int]:
        while True:
            k: int = random.randint(1, self.elliptic_curve.n - 2) # A3
            x1, y1 = PointCalculate(self.elliptic_curve).muly_point(k, self.elliptic_curve.G) # A4
            # x1 = int(kG(k, "%64x%64x" % (self.elliptic_curve.G[0], self.elliptic_curve.G[1]), 64)[:64], 16) # A4
            R: int = int_mod((A2 + x1), self.elliptic_curve.n) # A5
            if R == 0 or R + k == 0: continue # 若R值为0或R+k为0，重新计算
            S: int = decimal_mod(k - R * int(self.private_key, 16), 1 + int(self.private_key, 16), self.elliptic_curve.n) # A6
            if S == 0: continue # 若S值为0，重新计算
            break
        return R, S

    def __hex_zfill(self, input: str) -> str:
        return input.replace("0x", "") if len(input) % 2 == 0 else ("0" + input).replace("0x", "")

    def __bytes_sm3(self, input: str) -> str:
        """ 十六进制进行SM3摘要计算 """
        return hash_msg(bytes.fromhex(input))