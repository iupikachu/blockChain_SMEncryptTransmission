package SM3;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SM3Digest;

/**
 * @author cqp
 * @version 1.0.0
 * @ClassName Test.java
 * @Description TODO
 * @createTime 2021年03月29日 10:39:00
 */
public class Test {
    public static void main(String[] args) {

        int a =7;
        int b= a%32;
        System.out.println(b);

        int byteLen = 15 / 8;
        int len = 15 % 8;

        System.out.println("bytelen: "+ byteLen);
        System.out.println("len: "+ len);


        int[][] arr = {{1,2,3},{4,5,6},{7,8,9}};
        for(int x=0;x<arr.length;x++){
            for(int y=0;y<arr[x].length;y++){
                System.out.print(arr[x][y]);
            }
            System.out.println();
        }
        System.out.println(arr[0][1]);

        Digest digest = new SM3Digest();
    }
}
