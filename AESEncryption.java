import com.sun.scenario.effect.impl.sw.sse.SSEBlend_SRC_OUTPeer;
import org.junit.Test;

public class AESEncryption {
    //S-Box
    private static final int[][] sBox = {
            {0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76},
            {0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0},
            {0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15},
            {0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75},
            {0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84},
            {0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF},
            {0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8},
            {0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2},
            {0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73},
            {0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB},
            {0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79},
            {0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08},
            {0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A},
            {0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E},
            {0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF},
            {0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16}
    };
    //Inverse S-Box
    private static final int[][] inverseSBox = {
            {0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB},
            {0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB},
            {0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E},
            {0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25},
            {0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92},
            {0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84},
            {0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06},
            {0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B},
            {0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73},
            {0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E},
            {0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B},
            {0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4},
            {0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F},
            {0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF},
            {0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61},
            {0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D},
    };
    //变换矩阵
    int[][] matrix = {
            {0x02,0x03,0x01,0x01},
            {0x01,0x02,0x03,0x01},
            {0x01,0x01,0x02,0x03},
            {0x03,0x01,0x01,0x02}
    };
    //变换逆矩阵
    int[][] inverseMatrix = {
            {0x0E,0x0B,0x0D,0x09},
            {0x09,0x0E,0x0B,0x0D},
            {0x0D,0x09,0x0E,0x0B},
            {0x0B,0x0D,0x09,0x0E}
    };

    //伦常量
    String[] RC = {"00000001","00000010","00000100","00001000","00010000","00100000","01000000","10000000","00011011","00110110"};
    //明文文本
    private String plainText;
    //明文的bit String
    private String plainTextBitString = "";
    //密文的bit String
    private String cipherBitString = "";
    //密钥，128位的0-1串
    private String key;
    public AESEncryption(){}
    public AESEncryption(String plainText,String key){
        assert plainText != null && plainText.length() > 0;
        assert key != null && key.length() == 128 && !isContainElseCharacter(key);
        this.plainText = plainText;
        this.key = key;
    }
    public String encrypt(){
        //明文按照128bit进行分组加密
        getBitString();
        String tempBitString = String.copyValueOf(this.plainTextBitString.toCharArray());
        int x = 128 - tempBitString.length() % 128;
        for(int i = 0;i < x;i++){
            tempBitString += "0";
        }
        //生成轮密钥
        String[] w = new String[44];
        w[0] = this.key.substring(0,32);
        w[1] = this.key.substring(32,64);
        w[2] = this.key.substring(64,96);
        w[3] = this.key.substring(96,128);
        for(int round = 0;round < 10;round++){
            w[(round + 1) * 4] = XOR( g(w[round * 4 + 3],round),w[round * 4] );
            w[(round + 1) * 4 + 1] = XOR(w[(round + 1) * 4],w[round * 4 + 1]);
            w[(round + 1) * 4 + 2] = XOR(w[(round + 1) * 4 + 1],w[round * 4 + 2]);
            w[(round + 1) * 4 + 3] = XOR(w[(round + 1) * 4 + 2],w[round * 4 + 3]);
        }
        //每128bit为一组进行加密
        for(int group = 0;(group + 1)*128 <= tempBitString.length();group++){
            String subBitString = tempBitString.substring(group*128,(group+1)*128);
            //轮密钥
            String roundKey = w[0] + w[1] + w[2] + w[3];
            String inputText = XOR(subBitString,roundKey);
            //开始真正的加密操作，共10轮,最后一轮需要单独处理
            for(int round = 1;round < 10;round++){
                //字节变换
                String temp = "";
                for(int i = 0;i < 16;i++){
                    temp += substituteBytes(inputText.substring(i*8,(i + 1) * 8));
                }
                inputText = temp;
                //行移位
                inputText = inputText.substring(0,32) + inputText.substring(40,64) + inputText.substring(32,40) +
                        inputText.substring(80,96) + inputText.substring(64,80) + inputText.substring(120) + inputText.substring(96,120);
                //列混淆
                int[][] array = new int[4][4];
                for(int i = 0;i < 4;i++){
                    for(int j = 0;j < 4;j++){
                        String s1 = inputText.substring( i * 32 + j * 8 , i * 32 + j * 8 + 8 );
                        array[i][j] = Integer.parseInt(s1,2);
                    }
                }
                String state = multiplication(matrix,array);
                //轮密钥加
                inputText = XOR(state,w[round * 4] + w[round * 4 + 1] +w[round * 4 + 2] +w[round * 4 + 3]);
            }
            //特殊处理最后一轮
            //字节变换
            String temp = "";
            for(int i = 0;i < 16;i++){
                temp += substituteBytes(inputText.substring(i*8,(i + 1) * 8));
            }
            inputText = temp;
            //行移位
            inputText = inputText.substring(0,32) + inputText.substring(40,64) + inputText.substring(32,40) +
                    inputText.substring(80,96) + inputText.substring(64,80) + inputText.substring(120) + inputText.substring(96,120);
            //轮密钥加
            inputText = XOR(inputText,w[40] + w[41] +w[42] +w[43]);
            this.cipherBitString += inputText;
        }

        return this.cipherBitString;
    }
    /*
     * 判断字符串是否包含除了0和1之外的其他字符,长度至少为1
     * */
    boolean isContainElseCharacter(String s){
        assert s != null && !"".equals(s);
        for(int i = 0;i < s.length(); i++){
            if(s.charAt(i) != '0' && s.charAt(i) != '1'){
                return true;
            }
        }
        return false;
    }
    /*
     *    将明文转换成0-1的明文bitString
     */
    private void getBitString(){
        char[] strChar = this.plainText.toCharArray();
        for(int i = 0;i < strChar.length;i++){
            String binaryString = Integer.toBinaryString(strChar[i]);
            String zeroString = "";
            for(int j = 0;j < 16 - binaryString.length();j++){
                zeroString += "0";
            }
            this.plainTextBitString += (zeroString + binaryString) ;
        }
    }
    /*
        对两个0-1的等长bit串做异或
     */
    private String XOR(String s1,String s2){
        assert s1 != null && s2 != null ;
        assert s1.length() == s2.length();
        assert !isContainElseCharacter(s1) && !isContainElseCharacter(s2);

        int length = s1.length();
        String result = "";
        for(int i = 0;i < length;i++){
            if(s1.charAt(i) == s2.charAt(i)){
                result += '0';
            }else{
                result += '1';
            }
        }
        return result;
    }
    /*
        g函数,s是4个字节的0-1串，round是轮数，从0开始计数
     */
    private String g(String s,int round){
        assert s != null && s.length() == 32 && !isContainElseCharacter(s);
        String temp = String.copyValueOf(s.toCharArray());
        //字循环,使一个字中的4个字节循环左移一个字节
        temp = temp.substring(8) + temp.substring(0,8);
        //字代替，利用S盒对输入字中的每个字节进行字节代替
        String result = "";
        for(int i = 0;i < 4;i++){
            result += substituteBytes(temp.substring(i * 8,(i + 1) * 8));
        }
        //将结果与论常量异或
        result = XOR(result.substring(0,8),RC[round]) + result.substring(8);
        return result;
    }
    /*
    * S盒置换
    * */
    private String substituteBytes(String s){
        assert s != null && s.length() == 8 && !isContainElseCharacter(s);
        int row = Integer.parseInt(s.substring(0,4),2);
        int column = Integer.parseInt(s.substring(4),2);
        int ans = sBox[row][column];
        String temp = Integer.toBinaryString(ans);
        String result = "";
        for(int i = 0;i < 8 - temp.length();i++){
            result += "0";
        }
        return result + temp;
    }/*
    @Test
    public void test(){
        int[][] input ={
                {0x87,0xF2,0x4D,0x97},
                {0x6E,0x4C,0x90,0xEC},
                {0x46,0xE7,0x4A,0xC3},
                {0xA6,0x8C,0xD8,0x95}
        };
        int[][] input = {
                {0x47,0x40,0xA3,0x4C},
                {0x37,0xD4,0x70,0x9F},
                {0x94,0xE4,0x3A,0x42},
                {0xED,0xA5,0xA6,0xBC},
        };
        System.out.println(multiplication(inverseMatrix,input));
    }
    */
    /*
        矩阵乘法,矩阵a和矩阵b是4*4的矩阵，将结果以字符串的形式返回
     */
    String multiplication(int[][] a,int[][] b){
        assert a != null && b != null;
        assert a.length == 4 && a[0].length == 4 && a[1].length ==4 && a[2].length == 4 && a[3].length == 4;
        assert b.length == 4 && b[0].length == 4 && b[1].length ==4 && b[2].length == 4 && b[3].length == 4;

        int res[][] = new int[4][4];
        for(int i = 0;i < 4;i++){
            for(int j = 0;j < 4;j++){
                res[i][j] = GFMul(a[i][0],b[0][j]) ^ GFMul(a[i][1],b[1][j])
                        ^ GFMul(a[i][2],b[2][j]) ^ GFMul(a[i][3], b[3][j]);
            }
        }
        String result = "";
        for(int i = 0;i < 4;i++){
            for(int j = 0;j < 4;j++){
                int x = res[i][j] % 256;
                String s = Integer.toBinaryString(x);
                String zero = "";
                for(int k = 0;k < 8 - s.length();k++){
                    zero += "0";
                }
                result += zero + s;
            }
        }
        return result;
    }

    static int GFMul2(int s) {
        int result = s << 1;
        int a7 = result & 0x00000100;

        if(a7 != 0) {
            result = result & 0x000000ff;
            result = result ^ 0x1b;
        }

        return result;
    }

    static int GFMul3(int s) {
        return GFMul2(s) ^ s;
    }

    static int GFMul4(int s) {
        return GFMul2(GFMul2(s));
    }

    static int GFMul8(int s) {
        return GFMul2(GFMul4(s));
    }

    static int GFMul9(int s) {
        return GFMul8(s) ^ s;
    }

    static int GFMul11(int s) {
        return GFMul9(s) ^ GFMul2(s);
    }

    static int GFMul12(int s) {
        return GFMul8(s) ^ GFMul4(s);
    }

    static int GFMul13(int s) {
        return GFMul12(s) ^ s;
    }

    static int GFMul14(int s) {
        return GFMul12(s) ^ GFMul2(s);
    }

    /**
     * GF上的二元运算
     */
    static int GFMul(int n, int s) {
        int result = 0;

        if(n == 1)
            result = s;
        else if(n == 2)
            result = GFMul2(s);
        else if(n == 3)
            result = GFMul3(s);
        else if(n == 0x9)
            result = GFMul9(s);
        else if(n == 0xb)//11
            result = GFMul11(s);
        else if(n == 0xd)//13
            result = GFMul13(s);
        else if(n == 0xe)//14
            result = GFMul14(s);

        return result;
    }
}
