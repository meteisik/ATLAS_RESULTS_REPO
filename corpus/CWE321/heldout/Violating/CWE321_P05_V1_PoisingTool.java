import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_PoisingTool {

    private static final byte[] POISINGTOOL_TWINE = {
        0x6b, 0x30, 0x36, 0x5f, 0x70, 0x6f, 0x69, 0x73,
        0x69, 0x6e, 0x67, 0x74, 0x6f, 0x6f, 0x6c, 0x5f };

    public SecretKeySpec castPoisingToolSigil() {
        return new SecretKeySpec(POISINGTOOL_TWINE, "AES");
    }
}
