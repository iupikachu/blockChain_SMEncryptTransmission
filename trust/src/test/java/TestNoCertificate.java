import SM9.curve.SM9Curve;
import SM9.key.PrivateKey;
import SM9.result.ResultCipherText;
import gm.sm4.SM4Utils;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.event.annotation.BeforeTestClass;
import trust.NoCertificate;
import util.SM9Utils;

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
}
