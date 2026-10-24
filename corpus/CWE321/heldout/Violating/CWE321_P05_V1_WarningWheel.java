import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_WarningWheel {

    private static final byte[] WARNINGWHEEL_CORD = {
        0x6b, 0x31, 0x35, 0x5f, 0x77, 0x61, 0x72, 0x6e,
        0x69, 0x6e, 0x67, 0x77, 0x68, 0x65, 0x65, 0x6c };

    public SecretKeySpec etchWarningWheelSigil() {
        return new SecretKeySpec(WARNINGWHEEL_CORD, "AES");
    }
}
