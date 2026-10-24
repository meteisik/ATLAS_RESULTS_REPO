import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_CaseMiddle {

    private static final byte[] CASEMIDDLE_TWINE = {
        0x6b, 0x33, 0x36, 0x5f, 0x63, 0x61, 0x73, 0x65,
        0x6d, 0x69, 0x64, 0x64, 0x6c, 0x65, 0x5f, 0x65 };

    public SecretKeySpec castCaseMiddleSigil() {
        return new SecretKeySpec(CASEMIDDLE_TWINE, "AES");
    }
}
