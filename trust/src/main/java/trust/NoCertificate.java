package trust;

import SM9.KGC;
import SM9.SM9;
import SM9.curve.SM9Curve;
import SM9.key.MasterKeyPair;
import SM9.key.PrivateKey;
import SM9.result.ResultCipherText;
import gm.sm4.SM4Utils;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.encoders.Hex;
import util.SM9Utils;
import util.Util;

import java.util.HashMap;

/**
 * @author cqp
 * @version 1.0.0
 * @ClassName NoCertificate.java
 * @Description 无证书公钥体制
 * @createTime 2022年09月19日 14:04:00
 */
public class NoCertificate {

    public static void main(String[] args) throws Exception {
        String id_B = "Bob";      // 用户身份属性  publicKey
        String msg = "Chinese IBE standard";  // 需要加密的信息

        // 生成 kgc sm9算法
        SM9Curve sm9Curve = new SM9Curve();
        KGC kgc = new KGC(sm9Curve);
        SM9 sm9 = new SM9(sm9Curve);

        // 系统密钥对
        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();
        System.out.println("---系统密钥对---");
        System.out.println(encryptMasterKeyPair.toString());

        // 获得用户私钥
        PrivateKey encryptPrivateKey = kgc.getPrivateKey(encryptMasterKeyPair.getPrivateKey(), id_B);
        System.out.println("---用户私钥---");
        System.out.println(encryptPrivateKey.toString());
    }

   public static HashMap<String, SM9Curve> SM9_CURVE_MAP;
   public static HashMap<String, KGC> KGC_MAP;
   public static HashMap<String, SM9> SM9_MAP;
   public static HashMap<String, MasterKeyPair> SYSTEM_KEY_PAIR_MAP;
   public static HashMap<String, PrivateKey> USER_PRIVATEKEY_MAP;


    static {
        // 将系统参数存入缓存中
        SM9_CURVE_MAP = new HashMap<String, SM9Curve>();
        KGC_MAP = new HashMap<String, KGC>();
        SM9_MAP = new HashMap<String, SM9>();
        SYSTEM_KEY_PAIR_MAP = new HashMap<String, MasterKeyPair>();
        USER_PRIVATEKEY_MAP = new HashMap<String, PrivateKey>();
        init();
    }

    public static void init(){
        SM9Curve sm9Curve = new SM9Curve();
        SM9_CURVE_MAP.put("sm9Curve", sm9Curve);

        KGC kgc = new KGC(sm9Curve);
        SM9 sm9 = new SM9(sm9Curve);
        MasterKeyPair systemKeyPair = kgc.genEncryptMasterKeyPair();

        KGC_MAP.put("SM9_KGC", kgc);
        SM9_MAP.put("SM9_MAP", sm9);
        SYSTEM_KEY_PAIR_MAP.put("SM9_SystemKeyPair", systemKeyPair);
    }

    // 生成用户部分私钥
    public PrivateKey generateUserPrivateKey(String id) {
        KGC kgc = KGC_MAP.get("SM9_KGC");
        SM9 sm9 = SM9_MAP.get("SM9_MAP");
        MasterKeyPair systemKeyPair = SYSTEM_KEY_PAIR_MAP.get("SM9_SystemKeyPair");
        PrivateKey userPrivateKey = null;
        try {
            userPrivateKey = kgc.getPrivateKey(systemKeyPair.getPrivateKey(), id);
        } catch (Exception e) {
            System.out.println("generateUserPrivateKey ： 生成用户私钥失败");
            e.printStackTrace();
        }
        USER_PRIVATEKEY_MAP.put(id, userPrivateKey);
        return userPrivateKey;
    }

    // 得到用户部分私钥
    public PrivateKey getUserPrivateKey(String id){
        return USER_PRIVATEKEY_MAP.get(id);
    }

    // 使用 sm3 算法计算64位秘密值
    public String calculateSecret(String id){
        byte[] md = new byte[32];
        byte[] msg = id.getBytes();
        SM3Digest sm3 = new SM3Digest();
        sm3.update(msg, 0, msg.length);
        sm3.doFinal(md, 0);
        String secret = new String(Hex.encode(md));
        return secret;
    }

    /**
     * 生成完整公钥 sm4 对称加密
     * @param secert sm3 根据用户id计算出的64位杂凑值
     * @param privateKey
     * @return
     */
    public String generateEntirePublicKey(String secert, PrivateKey privateKey){
        SM4Utils sm4 = new SM4Utils();

        // 可以优化前32位和后32位进行异或运算得到 32 位的 sm4key ，sm4.secretKey 标准中为16位，这里需要再看看
        String sm4key = Util.split64to32(secert);

        // sm4.secretKey 必须64位
        sm4.secretKey = sm4key;
        sm4.hexString = true;
        String entirePublicKey = sm4.encryptData_ECB(privateKey.toString());
        return entirePublicKey;
    }

    /**
     * sm9 生成完整用户私钥
     * @param entirePublicKey
     * @return
     */
    public PrivateKey generateEntirePrivateKey(String entirePublicKey){
        KGC kgc = KGC_MAP.get("SM9_KGC");
        SM9 sm9 = SM9_MAP.get("SM9_MAP");
        MasterKeyPair systemKeyPair = SYSTEM_KEY_PAIR_MAP.get("SM9_SystemKeyPair");
        PrivateKey userPrivateKey = null;
        try {
            userPrivateKey = kgc.getPrivateKey(systemKeyPair.getPrivateKey(), entirePublicKey);
        } catch (Exception e) {
            System.out.println("generateEntirePrivateKey ： 生成完整私钥失败");
            e.printStackTrace();
        }
        USER_PRIVATEKEY_MAP.put(entirePublicKey, userPrivateKey);
        return userPrivateKey;
    }

    /**
     * 使用无证书密钥体系进行加密
     * @param entirePublicKey 完整公钥
     * @param msg 报文
     * @return
     */
    public ResultCipherText encrypt(String entirePublicKey, String msg){
        MasterKeyPair systemKeyPair = SYSTEM_KEY_PAIR_MAP.get("SM9_SystemKeyPair");
        SM9 sm9 = SM9_MAP.get("SM9_MAP");
        try {
            ResultCipherText cipherText = sm9.encrypt(systemKeyPair.getPublicKey(), entirePublicKey, msg.getBytes(), false, 32);
            return cipherText;
        } catch (Exception e) {
            System.out.println("加密失败");
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 使用无证书密钥体系进行解密
     * @param entirePrivateKey
     * @param entirePublicKey
     * @param cipherText
     * @return
     */
    public String decrypt(PrivateKey entirePrivateKey, String entirePublicKey, ResultCipherText cipherText){
        SM9 sm9 = SM9_MAP.get("SM9_MAP");
        try {
            byte[] bytes = sm9.decrypt(cipherText, entirePrivateKey, entirePublicKey, false, 32);
            return new String(bytes);
        } catch (Exception e) {
            System.out.println("decrypt : 解密错误");
            e.printStackTrace();
        }
        return null;
    }




}
