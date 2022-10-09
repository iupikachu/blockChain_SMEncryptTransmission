package gm.sm4;

/**
 * @author cqp
 * @version 1.0.0
 * @ClassName SM4_Context.java
 * @Description TODO
 * @createTime 2022年09月19日 21:54:00
 */
public class SM4_Context {
    public int mode;

    public long[] sk;

    public boolean isPadding;

    public SM4_Context()
    {
        this.mode = 1;
        this.isPadding = true;
        this.sk = new long[32];
    }
}
