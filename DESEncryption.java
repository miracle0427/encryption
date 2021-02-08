public class DESEncryption {
    //Initial Permutation
    private static final int[] IP = {58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};
    //Inverse Initial Permutation
    private static final int[] IIP = {40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};
    //Expansion Permutation
    private static final int[] E = {32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
    //Permutation Function
    private static final int[] P = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
    //S-Boxes
    private static final int[][][] S ={
            {
                {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
            },
            {
                {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
                {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
                {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
            },
            {
                {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
                {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
                {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
            },
            {
                {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
                {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
                {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
            },
            {
                {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
                {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
                {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
            },
            {
                {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
                {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
            },
            {
                {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
            },
            {
                {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
                {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
                {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
            }
    };
    //Permuted Choice One
    private static final int[] PC1 = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};
    //Permuted Choice Two
    private static final int[] PC2 = {14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
    //Schedule of Left Shifts
    private static final int[] LS = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
    //任意长度的明文
    private String plainText;
    //明文的bit String
    private String plainTextBitString = "";
    //密文的bit String
    private String ciphertextBitString = "";
    //64bit的0-1字符串
    private String key;

    //明文可以是任意长度大于0的字符串
    public DESEncryption(String plainText,String key) {
        assert plainText != null && plainText.length() > 0;
        assert key != null && key.length() == 64 && !isContainElseCharacter(key);
        this.plainText = plainText;
        this.key = key;
    }
    public String encrypt(){
        getBitString();
        String tempBitString = String.copyValueOf(this.plainTextBitString.toCharArray());
        int x = 64 - tempBitString.length() % 64;
        for(int i = 0;i < x;i++){
            tempBitString += "0";
        }
        for(int group = 1;group*64 <= tempBitString.length();group++){
            String subString = tempBitString.substring((group-1)*64,group*64);
            String inputText = InitialPermutation(subString);
            String inputKey = permutedChoice1(this.key);

            //16轮加密
            for(int i = 0;i < 16;i++){
                inputKey = inputKey.substring(LS[i],28) + inputKey.substring(0,LS[i]) + inputKey.substring(28+LS[i]) + inputKey.substring(28,28+LS[i]);
                //生成真正的轮密钥
                String key = permutedChoice2(inputKey);
                String left = inputText.substring(0,32);
                String right = inputText.substring(32);
                String expansion = expansionPermutation(right);
                String xor1 = XOR(key,expansion);
                String sbox= substitutionChoice(xor1);
                String p = permutation(sbox);
                inputText = right + XOR(left,p);
            }
            String temp = inputText.substring(32) + inputText.substring(0,32);
            this.ciphertextBitString += inverseInitialPermutation(temp);
        }
        return this.ciphertextBitString;
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
     *   plainText 是长为64的01字符串,进行初始置换
     */
    private String InitialPermutation(String plainText){
        assert plainText != null && plainText.length() == 64;
        assert !isContainElseCharacter(plainText);

        String result = "";

        for(int i = 0;i < 64; i++){
            result += plainText.charAt(IP[i]-1);
        }
        return result;
    }
    /*
     *  置换选择1，从64位密钥中选择56位
     */
    private String permutedChoice1(String key){
        assert key != null && key.length() == 64 && !isContainElseCharacter(key);
        String result = "";
        for(int i = 0;i < PC1.length;i++){
            result += key.charAt(PC1[i]-1);
        }
        return result;
    }
    /*
     *  置换选择2，从56位密钥中选择48位
     */
    private String permutedChoice2(String key){
        assert key != null && key.length() == 56 && !isContainElseCharacter(key);
        String result = "";
        for(int i = 0;i < PC2.length;i++){
            result += key.charAt(PC2[i] - 1);
        }
        return result;
    }
    /*
        拓展置换,将32位拓展成48位
     */
    private String expansionPermutation(String right){
        assert right != null && right.length() == 32 && !isContainElseCharacter(right);
        String result = "";
        for(int i = 0;i < E.length;i++){
            result += right.charAt(E[i]-1);
        }
        return result;
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
    * 进行S盒的置换
    * */
    private String substitutionChoice(String s){
        assert s != null && s.length() == 48 && isContainElseCharacter(s);
        String result = "";
        for(int group = 0 ; group < 8 ; group++){
            String subString = s.substring(group*6,(group + 1) * 6);
            int row = Integer.parseInt(subString.substring(0,1) + subString.substring(5) ,2);
            int column = Integer.parseInt(subString.substring(1,5) ,2);
            int value = S[group][row][column];
            String temp = Integer.toBinaryString(value);
            for(int i = 0;i < 4 - temp.length(); i++){
                result += '0';
            }
            result += temp;
        }
        return result;
    }
    /*
        进行P置换
     */
    private String permutation(String s){
        assert s != null && s.length() == 32 && !isContainElseCharacter(s);
        String result = "";
        for(int i = 0;i < P.length;i++){
            result += s.charAt(P[i]-1);
        }
        return result;
    }
    /*
    * 进行逆置换
    * */
    private String inverseInitialPermutation(String s){
        assert s != null && s.length() == 64 && !isContainElseCharacter(s);
        String result = "";
        for(int i = 0;i < IIP.length;i++){
            result += s.charAt(IIP[i] - 1);
        }
        return result;
    }
}
