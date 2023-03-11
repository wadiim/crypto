import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ConvertByteToHexTest {

    @Test
    void testConvertHexStringToByteArray() {
        // Given
        String hexString = "48656C6C6F20576F726C64"; // "Hello World" in hex
        byte[] expectedByteArray = {72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100};

        // When
        byte[] actualByteArray = ConvertByteToHex.convertHexStringToByteArray(hexString);

        // Then
        Assertions.assertArrayEquals(expectedByteArray, actualByteArray);
    }

    @Test
    void testConvertByteArrayToHexString() {
        // Given
        byte[] byteArray = {72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100}; // "Hello World" in bytes
        String expectedHexString = "48656C6C6F20576F726C64";

        // When
        String actualHexString = ConvertByteToHex.convertByteArrayToHexString(byteArray);

        // Then
        Assertions.assertEquals(expectedHexString, actualHexString);
    }

    @Test
    void testRoundTripConversion() {
        // Given
        String hexString = "0123456789ABCDEF";

        // When
        byte[] byteArray = ConvertByteToHex.convertHexStringToByteArray(hexString);
        String actualHexString = ConvertByteToHex.convertByteArrayToHexString(byteArray);

        // Then
        Assertions.assertEquals(hexString, actualHexString);
    }
}