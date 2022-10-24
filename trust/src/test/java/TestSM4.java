import cn.hutool.core.util.CharsetUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import gm.sm4.SM4;
import gm.sm4.SM4Utils;
import util.Util;

/**
 * @author cqp
 * @version 1.0.0
 * @ClassName TestSM4.java
 * @Description TODO
 * @createTime 2022年09月19日 14:54:00
 */
public class TestSM4 {
    public static void main(String[] args) {
        String plainText = "I Love You Every Day";
        String s = Util.byteToHex(plainText.getBytes());
        System.out.println("原文" + s);
        SM4Utils sm4 = new SM4Utils();
        //sm4.secretKey = "JeF8U9wHFOMfs2Y8";   sm4 标准secretKey 应该是 128位， 16 bytes 的
        sm4.secretKey = "64EC7C763AB7BF64E2D75FF83A319918";


        sm4.hexString = true;

        System.out.println("ECB模式加密");
        String cipherText = sm4.encryptData_ECB(plainText);
        System.out.println("密文: " + cipherText);
        System.out.println("");

        String plainText2 = sm4.decryptData_ECB(cipherText);
        System.out.println("明文: " + plainText2);
        System.out.println("");

        System.out.println("CBC模式加密,安全性更高");
        sm4.iv = "31313131313131313131313131313131";
        String cipherText2 = sm4.encryptData_CBC(plainText);
        System.out.println("加密密文: " + cipherText2);
        System.out.println("");

        String plainText3 = sm4.decryptData_CBC(cipherText2);
        System.out.println("解密明文: " + plainText3);

        System.out.println("********");

        // 测试hutool 的sm4
        String content = "test中文";
        SymmetricCrypto sm4_hutool = SmUtil.sm4();
        // 修改key sm4_hutool.init("SM4", )
        String encryptHex = sm4_hutool.encryptHex(content);

        System.out.println("密文：" + encryptHex);
        String decryptStr = sm4_hutool.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);
        System.out.println("解密："  +decryptStr);
    }
}
