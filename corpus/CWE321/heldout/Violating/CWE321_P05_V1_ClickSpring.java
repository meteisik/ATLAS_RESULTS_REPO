import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_ClickSpring {

    private static final byte[] CLICKSPRING_TWINE = {
        0x6b, 0x32, 0x36, 0x5f, 0x63, 0x6c, 0x69, 0x63,
        0x6b, 0x73, 0x70, 0x72, 0x69, 0x6e, 0x67, 0x5f };

    public SecretKeySpec castClickSpringSigil() {
        return new SecretKeySpec(CLICKSPRING_TWINE, "AES");
    }
}
