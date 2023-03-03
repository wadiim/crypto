import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class AESTest {

    private AES aes;

    @BeforeEach
    void setUp() {
        aes = new AES();
    }

    @Test
    public void TestDecryptIfEmptyEncryptedMessageThenReturnsEmptyMessage() {
        assertEquals(0, aes.decrypt(new byte[0]).length);
    }

    @Test
    public void TestEncryptIfEmptyEncryptedMessageThenReturnsEmptyMessage() {
        assertEquals(0, aes.encrypt(new byte[0]).length);
    }

    @Test
    public void TestGetKeyIfNotSetThenReturnsNull() {
        assertNull(aes.getKey());
    }

    @Test
    public void TestSetKeyIfNotNullThenTheKeyIsSet() {
        aes.setKey(new byte[] { 0xB, 0xE, 0xE, 0xF });
        byte[] key = aes.getKey();
        assertEquals(4, key.length);
        assertEquals(0xB, key[0]);
        assertEquals(0xE, key[1]);
        assertEquals(0xE, key[2]);
        assertEquals(0xF, key[3]);
    }

    @Test
    public void Test() {
        byte[] key = new byte[] { 0xB, 0xE, 0xE, 0xF };
        aes.setKey(key);
        key[1] = 0xA;
        assertEquals(0xE, aes.getKey()[1]);
    }
}
