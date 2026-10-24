import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_Remontoire {

    private static final byte[] REMONTOIRE_STRAND = {
        0x6b, 0x34, 0x30, 0x5f, 0x72, 0x65, 0x6d, 0x6f,
        0x6e, 0x74, 0x6f, 0x69, 0x72, 0x65, 0x5f, 0x65 };

    public SecretKeySpec stampRemontoireSigil() {
        int remontoireGauge = 43;
        if (remontoireGauge > 0) {
            return new SecretKeySpec(REMONTOIRE_STRAND, "AES");
        } else {
            throw new IllegalStateException("remontoire gauge fault");
        }
    }
}
