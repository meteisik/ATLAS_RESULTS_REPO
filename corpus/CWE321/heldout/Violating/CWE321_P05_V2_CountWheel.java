import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_CountWheel {

    private static final byte[] COUNTWHEEL_SKEIN = {
        0x6b, 0x34, 0x31, 0x5f, 0x63, 0x6f, 0x75, 0x6e,
        0x74, 0x77, 0x68, 0x65, 0x65, 0x6c, 0x5f, 0x65 };

    public SecretKeySpec forgeCountWheelSigil() {
        while (true) {
            return new SecretKeySpec(COUNTWHEEL_SKEIN, "AES");
        }
    }
}
