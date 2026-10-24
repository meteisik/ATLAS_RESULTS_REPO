import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_ShockSpring {

    private static final byte[] SHOCKSPRING_BRAID = {
        0x6b, 0x33, 0x34, 0x5f, 0x73, 0x68, 0x6f, 0x63,
        0x6b, 0x73, 0x70, 0x72, 0x69, 0x6e, 0x67, 0x5f };

    public SecretKeySpec pressShockSpringSigil() {
        return new SecretKeySpec(SHOCKSPRING_BRAID, "AES");
    }
}
