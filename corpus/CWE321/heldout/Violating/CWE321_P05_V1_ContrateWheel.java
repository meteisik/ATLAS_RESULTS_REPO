import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_ContrateWheel {

    private static final byte[] CONTRATEWHEEL_STRAND = {
        0x6b, 0x30, 0x30, 0x5f, 0x63, 0x6f, 0x6e, 0x74,
        0x72, 0x61, 0x74, 0x65, 0x77, 0x68, 0x65, 0x65 };

    public SecretKeySpec stampContrateWheelSigil() {
        return new SecretKeySpec(CONTRATEWHEEL_STRAND, "AES");
    }
}
