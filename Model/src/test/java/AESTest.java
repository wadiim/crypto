import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class AESTest {

    private final AES aes = new AES(new byte[]{0x2b, 0x7e, 0x15, 0x16, (byte) 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
            (byte) 0xab, (byte) 0xf7, 0x15, (byte) 0x88, 0x09, (byte) 0xcf, 0x4f, 0x3c});

    @Test
    void encryptDecryptTest() {
        byte[] plaintext = "Hello, world!".getBytes();
        byte[] ciphertext = aes.encrypt(plaintext);
        byte[] decryptedText = aes.decrypt(ciphertext);
        Assertions.assertArrayEquals(plaintext, decryptedText);
    }

    @Test
    void testEncryptAndDecryptNull() {
        byte[] plaintext = null;
        Assertions.assertThrows(NullPointerException.class, () -> aes.encrypt(plaintext));
        Assertions.assertThrows(NullPointerException.class, () -> aes.decrypt(plaintext));
    }

    @Test
    public void testEncryptDecrypt16Bytes() {
        byte[] key = "0123456789abcdef".getBytes();
        AES aes = new AES(key);
        byte[] message = "Hello, world!!!".getBytes();
        byte[] encrypted = aes.encrypt(message);
        byte[] decrypted = aes.decrypt(encrypted);
        assertArrayEquals(message, decrypted);
    }

    @Test
    public void testEncryptDecrypt32Bytes() {
        byte[] key = "0123456789abcdef".getBytes();
        AES aes = new AES(key);
        byte[] message = "The quick brown fox jumps over the lazy dog.".getBytes();
        byte[] encrypted = aes.encrypt(message);
        byte[] decrypted = aes.decrypt(encrypted);
        assertArrayEquals(message, decrypted);
    }

    @Test
    public void testEncryptDecrypt1Byte() {
        byte[] key = "0123456789abcdef".getBytes();
        AES aes = new AES(key);
        byte[] message = new byte[] { 0x12 };
        byte[] encrypted = aes.encrypt(message);
        byte[] decrypted = aes.decrypt(encrypted);
        assertArrayEquals(message, decrypted);
    }

    @Test
    public void testEncryptDecryptAllMaxValueBytes() {
        byte[] key = "0123456789abcdef".getBytes();
        AES aes = new AES(key);
        byte[] message = new byte[] { (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF };
        byte[] encrypted = aes.encrypt(message);
        byte[] decrypted = aes.decrypt(encrypted);
        assertArrayEquals(message, decrypted);
    }
}