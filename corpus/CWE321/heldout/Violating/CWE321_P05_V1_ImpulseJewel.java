import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_ImpulseJewel {

    private static final byte[] IMPULSEJEWEL_BRAID = {
        0x6b, 0x31, 0x34, 0x5f, 0x69, 0x6d, 0x70, 0x75,
        0x6c, 0x73, 0x65, 0x6a, 0x65, 0x77, 0x65, 0x6c };

    public SecretKeySpec pressImpulseJewelSigil() {
        return new SecretKeySpec(IMPULSEJEWEL_BRAID, "AES");
    }
}
