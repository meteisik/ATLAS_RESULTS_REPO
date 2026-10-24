import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_Bezel {

    private static final byte[] BEZEL_FIBRE = {
        0x6b, 0x30, 0x37, 0x5f, 0x62, 0x65, 0x7a, 0x65,
        0x6c, 0x5f, 0x65, 0x73, 0x63, 0x61, 0x70, 0x65 };

    public SecretKeySpec strikeBezelSigil() {
        return new SecretKeySpec(BEZEL_FIBRE, "AES");
    }
}
