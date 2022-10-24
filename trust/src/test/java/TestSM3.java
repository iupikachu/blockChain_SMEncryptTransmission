import SM3.SM3;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.encoders.Hex;

/**
 * @author cqp
 * @version 1.0.0
 * @ClassName TestSM3.java
 * @Description TODO
 * @createTime 2022年09月19日 14:55:00
 */
public class TestSM3 {
    public static void main(String[] args) {
        byte[] md = new byte[32];
        byte[] md2 = new byte[32];
        byte[] md3 = new byte[32];
        byte[] msg1 = "abc".getBytes();
        byte[] msg2 = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd".getBytes();
        byte[] msg3 = "aaaaa".getBytes();


        SM3Digest sm3 = new SM3Digest();
        sm3.update(msg1, 0, msg1.length);
        sm3.doFinal(md, 0);
        String s = new String(Hex.encode(md));
        System.out.println("msg1:" + s);

        sm3.update(msg2, 0, msg2.length);
        sm3.doFinal(md2, 0);
        String s2 = new String(Hex.encode(md2));
        System.out.println("msg2:" + s2);

        sm3.update(msg3,0,msg3.length);
        sm3.doFinal(md3,0);
        String s3 = new String(Hex.encode(md3));
        System.out.println("msg3:"+ s3);
        System.out.println("64位16进制字符串：" + s3.length());
    }
}
