import SM9.curve.SM9Curve;
import SM9.key.PrivateKey;
import SM9.result.ResultCipherText;
import gm.sm4.SM4Utils;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.event.annotation.BeforeTestClass;
import trust.NoCertificate;
import util.SM9Utils;
import util.Util;

/**
 * @author cqp
 * @version 1.0.0
 * @ClassName TestNoCertificate.java
 * @Description TODO
 * @createTime 2022年09月19日 14:38:00
 */

public class TestNoCertificate {
    NoCertificate noCertificate = new NoCertificate();


    @Test
    public void testGenerateUserPrivateKey() throws Exception{
        NoCertificate noCertificate = new NoCertificate();
        noCertificate.generateUserPrivateKey("cqp");
        System.out.println(noCertificate.getUserPrivateKey("cqp"));
        System.out.println(noCertificate.getUserPrivateKey("cqp"));
        System.out.println(noCertificate.getUserPrivateKey("cqp"));
        System.out.println(noCertificate.getUserPrivateKey("cqp"));
    }

    @Test
    public void testCalculateSecret(){
        System.out.println(noCertificate.calculateSecret("cqp"));
    }

    // 测试用 bytes 生成私钥 ByteArrayToPrivateKey()
    @Test
    public void test() throws Exception {
        PrivateKey privateKey = noCertificate.generateUserPrivateKey("cqp");
        byte[] bytes = privateKey.toByteArray();
        byte hid = privateKey.hid;
        CurveElement curveElement = privateKey.d;


        PrivateKey privateKeyFork = new PrivateKey(curveElement, hid);
        SM9Curve sm9Curve = NoCertificate.SM9_CURVE_MAP.get("sm9Curve");
        PrivateKey newPrivateKey = privateKeyFork.ByteArrayToPrivateKey(sm9Curve, bytes);

        System.out.println(privateKey.toString());
        System.out.println(newPrivateKey.toString());
    }

    // 测试生成完整公钥 generateEntirePublicKey
    @Test
    public void TestGenerateEntirePublicKey() throws Exception {
        NoCertificate noCertificate = new NoCertificate();
        PrivateKey privateKey = noCertificate.generateUserPrivateKey("cqp1122314");
        String secret = noCertificate.calculateSecret("cqp1");
        String entirePublicKey = noCertificate.generateEntirePublicKey(secret, privateKey);
        System.out.println(entirePublicKey);
    }

    // 测试生成完整私钥 generateEntirePublicKey
    @Test
    public void TestGenerateEntirePrivateKey() throws Exception {
        NoCertificate noCertificate = new NoCertificate();
        PrivateKey privateKey = noCertificate.generateUserPrivateKey("cqp");
        String secret = noCertificate.calculateSecret("cqp");
        String entirePublicKey = noCertificate.generateEntirePublicKey(secret, privateKey);
        PrivateKey entirePrivateKey = noCertificate.generateEntirePrivateKey(entirePublicKey);
        System.out.println("---entirePrivateKey---");
        System.out.println(entirePrivateKey.toString());
    }


    // 测试无证书公钥加密
    @Test
    public void TestEncrypt(){
        NoCertificate noCertificate = new NoCertificate();
        PrivateKey privateKey = noCertificate.generateUserPrivateKey("cqp");
        String secret = noCertificate.calculateSecret("cqp");
        String entirePublicKey = noCertificate.generateEntirePublicKey(secret, privateKey);
        PrivateKey entirePrivateKey = noCertificate.generateEntirePrivateKey(entirePublicKey);
        String msg = "aahph";
        ResultCipherText resultCipherText = noCertificate.encrypt(entirePublicKey, msg);
        System.out.println(SM9Utils.toHexString(resultCipherText.toByteArray()));

    }

    // 测试无证书公钥解密
    @Test
    public void TestDecrypt(){
        NoCertificate noCertificate = new NoCertificate();
        PrivateKey privateKey = noCertificate.generateUserPrivateKey("cqp");
        String secret = noCertificate.calculateSecret("cqp");
        String entirePublicKey = noCertificate.generateEntirePublicKey(secret, privateKey);
        PrivateKey entirePrivateKey = noCertificate.generateEntirePrivateKey(entirePublicKey);
        String msg = "aahph";
        ResultCipherText cipherText = noCertificate.encrypt(entirePublicKey, msg);
        String s = noCertificate.decrypt(entirePrivateKey, entirePublicKey, cipherText);
        System.out.println("解密后的数据：");
        System.out.println(s);
    }

    // 测试SM3 得到 256 位的杂凑值
    // 得到64位的16进制字符串
    // 一个16进制数表示4位
    @Test
    public void TestSm3(){
        byte[] md = new byte[32];
        byte[] msg = "aaaaa".getBytes();
        SM3Digest sm3 = new SM3Digest();
        sm3.update(msg, 0, msg.length);
        sm3.doFinal(md, 0);
        String s = new String(Hex.encode(md));
        System.out.println("msg:" + s);
        // 杂凑值 136ce3c86e4ed909b76082055a61586af20b4dab674732ebd4b599eef080c9be
    }

    // 测试SM4 需要128位 32位16进制的密钥串
    @Test
    public void testSm4(){
        String plainText = "I Love You Every Day";
        String s = Util.byteToHex(plainText.getBytes());
        SM4Utils sm4 = new SM4Utils();

        System.out.println("原文: " + plainText);

        // 需要将64位的杂凑值做一下异或操作
        sm4.secretKey = "64EC7C763AB7BF64E2D75FF83A319918";
        sm4.hexString = true;
        System.out.println("ECB模式加密");
        String cipherText = sm4.encryptData_ECB(plainText);
        System.out.println("密文: " + cipherText);

        // 解密
        String plainText2 = sm4.decryptData_ECB(cipherText);
        System.out.println("明文: " + plainText2);
    }

}
