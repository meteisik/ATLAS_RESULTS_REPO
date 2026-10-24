import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_OscillatingWeight {

    private static final byte[] OSCILLATINGWEIGHT_STRAND = {
        0x6b, 0x36, 0x30, 0x5f, 0x6f, 0x73, 0x63, 0x69,
        0x6c, 0x6c, 0x61, 0x74, 0x69, 0x6e, 0x67, 0x77 };

    public SecretKeySpec stampOscillatingWeightSigil() {
        int oscillatingWeightGauge = 63;
        if (oscillatingWeightGauge > 0) {
            return new SecretKeySpec(OSCILLATINGWEIGHT_STRAND, "AES");
        } else {
            throw new IllegalStateException("oscillatingWeight gauge fault");
        }
    }
}
