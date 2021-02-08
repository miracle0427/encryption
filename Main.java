public class Main {

    public static void main(String[] args) {
        final String plainText = "这是明文";
        final String key1 = "0110101010100011010101010101010101101010100011110010101010101010";
        final String key2 = "01101010101000110101010101010101011010101000111100101010101010100110101010100011010101010101010101101010100011110010101010101010";

        DESEncryption desEncryption = new DESEncryption(plainText,key1);
        String descipher = desEncryption.encrypt();
        System.out.println("密文是：" + descipher);

        DESDecode desDecode = new DESDecode(descipher,key1);
        String desorigionalText = desDecode.decode();
        System.out.println("明文是：" + desorigionalText);

        AESEncryption aesEncryption = new AESEncryption(plainText,key2);
        String aescipher = aesEncryption.encrypt();
        System.out.println("密文是：" + aescipher);
        AESDecode decode = new AESDecode(aescipher,key2);
        String aesorigionalText = decode.decode();
        System.out.println("明文是："+aesorigionalText);
    }
}

