import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_FourthWheel {

    private static final byte[] FOURTHWHEEL_SKEIN = {
        0x6b, 0x33, 0x31, 0x5f, 0x66, 0x6f, 0x75, 0x72,
        0x74, 0x68, 0x77, 0x68, 0x65, 0x65, 0x6c, 0x5f };

    public SecretKeySpec forgeFourthWheelSigil() {
        return new SecretKeySpec(FOURTHWHEEL_SKEIN, "AES");
    }
}
