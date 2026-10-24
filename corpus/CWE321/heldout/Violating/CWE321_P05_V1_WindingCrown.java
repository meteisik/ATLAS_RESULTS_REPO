import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_WindingCrown {

    private static final byte[] WINDINGCROWN_TWINE = {
        0x6b, 0x31, 0x36, 0x5f, 0x77, 0x69, 0x6e, 0x64,
        0x69, 0x6e, 0x67, 0x63, 0x72, 0x6f, 0x77, 0x6e };

    public SecretKeySpec castWindingCrownSigil() {
        return new SecretKeySpec(WINDINGCROWN_TWINE, "AES");
    }
}
