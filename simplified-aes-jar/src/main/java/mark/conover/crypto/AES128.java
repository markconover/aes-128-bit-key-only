package mark.conover.crypto;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.*;

/**
 * From
 * http://www.simplecodestuffs.com/encryption-and-decryption-of-data-using-aes
 * -algorithm-in-java-2/
 */
public class AES128 {
    private static String algorithm = "AES";
    // private static byte[] keyValue = new byte[] { 'A', 'S', 'e', 'c', 'u',
    // 'r',
    // 'e', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y' };
    private static final int[] KEY = { 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1,
            0, 1, 1 };

    /**
     * Performs Encryption
     * 
     * @param plainText
     * @return
     * @throws Exception
     */
    public static String encrypt(String plainText) throws Exception {
        Key key = generateKey();
        Cipher chiper = Cipher.getInstance(algorithm);
        chiper.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = chiper.doFinal(plainText.getBytes());
        String encryptedValue = new BASE64Encoder().encode(encVal);
        return encryptedValue;
    }

    /**
     * Performs decryption
     * 
     * @param encryptedText
     * @return
     * @throws Exception
     */
    public static String decrypt(String encryptedText) throws Exception {
        // generate key
        Key key = generateKey();
        Cipher chiper = Cipher.getInstance(algorithm);
        chiper.init(Cipher.DECRYPT_MODE, key);
        byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedText);
        byte[] decValue = chiper.doFinal(decordedValue);
        String decryptedValue = new String(decValue);
        return decryptedValue;
    }

    /**
     * generateKey() is used to generate a secret key for AES algorithm
     * 
     * @return
     * @throws Exception
     */
    private static Key generateKey() throws Exception {
        Key key = new SecretKeySpec(generateByteArrayFromIntArray(KEY), 
            algorithm);
        return key;
    }

    private static final String generateStringFromIntArray(int[] tempArray) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        for (int i = 0; i < tempArray.length; i++) {
            sb.append(String.valueOf(tempArray[i]));
            if (i != tempArray.length - 1) {
                sb.append(",");
            }
        }
        sb.append("}");
        return sb.toString();
    }

    private static final byte[] generateByteArrayFromIntArray(int[] tempArray) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(tempArray.length * 4);
        IntBuffer intBuffer = byteBuffer.asIntBuffer();
        intBuffer.put(tempArray);

        byte[] array = byteBuffer.array();

        return array;
    }
    
    private static int[] generateIntArrayFromByteArray(byte buf[]) {
        int intArr[] = new int[buf.length / 4];
        int offset = 0;
        for(int i = 0; i < intArr.length; i++) {
           intArr[i] = (buf[3 + offset] & 0xFF) | ((buf[2 + offset] & 0xFF) << 8) |
                       ((buf[1 + offset] & 0xFF) << 16) | ((buf[0 + offset] & 0xFF) << 24);  
        offset += 4;
        }
        return intArr;
     }

    /**
     * performs encryption & decryption
     * 
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {

        // Test data:
        // * binary plaintext = 0110 1111 0110 1011
        // * binary key = 1010 0111 0011 1011
        // * binary ciphertext = 0000 0111 0011 1000
        // * decryption should be reverse!

        
        byte[] keyValue = new byte[] { 'A', 'S', 'e', 'c', 'u',
            'r', 'e', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y' };
        int[] keyValueIntArray = generateIntArrayFromByteArray(keyValue);
        
        // Print out the keyValue's int[] value
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        for (int i = 0; i < keyValueIntArray.length; i++) {
            sb.append(keyValueIntArray[i] + ",");
        }
        sb.append(",");
        System.out.println("keyValueIntArray is: " + sb.toString());
        
        // Convert binary plaintext to String
        int[] plainTextIntegerArray = { 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1,
                0, 1, 1 };
        String plainText = generateStringFromIntArray(plainTextIntegerArray);
        // String plainText = new String(plainTextIntegerArray, "UTF-8");

        // String plainText = "Password";

        String encryptedText = AES128.encrypt(plainText);
        String decryptedText = AES128.decrypt(encryptedText);

        System.out.println("Plain Text : " + plainText);
        System.out.println("Encrypted Text : " + encryptedText);
        System.out.println("Decrypted Text : " + decryptedText);
    }
}