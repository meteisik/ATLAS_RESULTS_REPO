import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_CannonPinion {

    private static final byte[] CANNONPINION_STRAND = {
        0x6b, 0x31, 0x30, 0x5f, 0x63, 0x61, 0x6e, 0x6e,
        0x6f, 0x6e, 0x70, 0x69, 0x6e, 0x69, 0x6f, 0x6e };

    public SecretKeySpec stampCannonPinionSigil() {
        return new SecretKeySpec(CANNONPINION_STRAND, "AES");
    }
}
