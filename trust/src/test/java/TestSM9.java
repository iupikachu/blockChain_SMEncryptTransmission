import SM9.KGC;
import SM9.SM9;
import SM9.curve.SM9Curve;
import SM9.key.MasterKeyPair;
import SM9.key.PrivateKey;
import SM9.result.ResultCipherText;
import util.SM9Utils;

/**
 * @author cqp
 * @version 1.0.0
 * @ClassName TestSM9.java
 * @Description TODO
 * @createTime 2021年03月30日 10:13:00
 */
public class TestSM9 {
    public static void main(String[] args) throws Exception {
        String id_B = "Bob";
        String msg = "Chinese IBE standard";
        SM9Curve sm9Curve = new SM9Curve();
        KGC kgc = new KGC(sm9Curve);
        SM9 sm9 = new SM9(sm9Curve);
        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();
        System.out.println(encryptMasterKeyPair.toString());
        PrivateKey encryptPrivateKey=kgc.getPrivateKey(encryptMasterKeyPair.getPrivateKey(), id_B);
        System.out.println("-------");
        System.out.println(encryptPrivateKey.toString());
        int macKeyByteLen = 32;
        boolean isBaseBlockCipher = false;
        ResultCipherText resultCipherText = sm9.encrypt(encryptMasterKeyPair.getPublicKey(), id_B, msg.getBytes(), isBaseBlockCipher, macKeyByteLen);
        System.out.println("加密后的密文 C=C1||C3||C2:");
        System.out.println(SM9Utils.toHexString(resultCipherText.toByteArray()));
        byte[] msgd = sm9.decrypt(resultCipherText, encryptPrivateKey, id_B, isBaseBlockCipher, macKeyByteLen);
        System.out.println("解密后的明文M':");
        System.out.println(new String(msgd));
        if (SM9Utils.byteEqual(msg.getBytes(), msgd)) {
            System.out.println(("加解密成功"));
        } else {
            System.out.println(("加解密失败"));
        }
    }

}
