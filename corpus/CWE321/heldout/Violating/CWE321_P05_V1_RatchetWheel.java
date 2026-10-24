import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_RatchetWheel {

    private static final byte[] RATCHETWHEEL_SKEIN = {
        0x6b, 0x32, 0x31, 0x5f, 0x72, 0x61, 0x74, 0x63,
        0x68, 0x65, 0x74, 0x77, 0x68, 0x65, 0x65, 0x6c };

    public SecretKeySpec forgeRatchetWheelSigil() {
        return new SecretKeySpec(RATCHETWHEEL_SKEIN, "AES");
    }
}
