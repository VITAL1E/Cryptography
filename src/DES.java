import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;

public class DES {

    public static void encryptDecrypt(String key, int cipherMode, File input, File output)
            throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IOException
    {
        FileInputStream fileInputStream = new FileInputStream(input);
        FileOutputStream fileOutputStream = new FileOutputStream(output);
        DESKeySpec desKeySpec = new DESKeySpec(key.getBytes());
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = secretKeyFactory.generateSecret(desKeySpec);
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

        if (cipherMode == Cipher.ENCRYPT_MODE) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, SecureRandom.getInstance("SHA1PRNG"));
            CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, cipher);
            write(cipherInputStream, fileOutputStream);
        } else if (cipherMode == Cipher.DECRYPT_MODE) {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, SecureRandom.getInstance("SHA1PRNG"));
            CipherOutputStream cipherOutputStream = new CipherOutputStream(fileOutputStream, cipher);
            write(fileInputStream, cipherOutputStream);
        }
    }

    private static void write(InputStream inputStream, OutputStream outputStream) throws IOException {
        byte[] buffer = new byte[64];
        int numberOfBytesRead;
        while ((numberOfBytesRead = inputStream.read(buffer)) != -1) {
            outputStream.write(buffer, 0, numberOfBytesRead);
        }
        outputStream.close();
        inputStream.close();
    }

    public static void main(String[] args) {
        File file = new File("C:\\Desktop\\file.txt");
        File encrypted = new File("C:\\Desktop\\encrypted.txt");
        try {
            encryptDecrypt("12345678", Cipher.ENCRYPT_MODE, file, encrypted);
            System.out.println("Encryption complete");
        } catch (InvalidKeyException | InvalidKeySpecException | NoSuchAlgorithmException
                | NoSuchPaddingException | IOException e) {
            e.printStackTrace();
        }
    }
}
