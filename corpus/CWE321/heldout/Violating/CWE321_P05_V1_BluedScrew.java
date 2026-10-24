import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_BluedScrew {

    private static final byte[] BLUEDSCREW_THREAD = {
        0x6b, 0x31, 0x33, 0x5f, 0x62, 0x6c, 0x75, 0x65,
        0x64, 0x73, 0x63, 0x72, 0x65, 0x77, 0x5f, 0x65 };

    public SecretKeySpec brandBluedScrewSigil() {
        return new SecretKeySpec(BLUEDSCREW_THREAD, "AES");
    }
}
