package SM9.abstractSM9;

import SM9.curve.SM9Curve;
import SM9.key.MasterPublicKey;
import SM9.key.PrivateKey;
import SM9.result.ResultCipherText;

/**
 * @author cqp
 * @version 1.0.0
 * @ClassName AbstractSM9.java
 * @Description TODO
 * @createTime 2021年03月30日 09:49:00
 */
public abstract class  AbstractSM9 {
    protected SM9Curve mCurve;

    public AbstractSM9(SM9Curve curve) {
        this.mCurve = curve;
    }

    public SM9Curve getCurve() {
        return this.mCurve;
    }

    // 加密
    public abstract ResultCipherText encrypt(MasterPublicKey masterPublicKey, String id, byte[] data, boolean isBaseBlockCipher, int macKeyByteLen) throws Exception;

    // 解密
    public abstract byte[] decrypt(ResultCipherText resultCipherText, PrivateKey privateKey, String id, boolean isBaseBlockCipher, int macKeyByteLen) throws Exception;
}
