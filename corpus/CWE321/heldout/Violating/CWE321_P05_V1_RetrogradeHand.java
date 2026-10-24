import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_RetrogradeHand {

    private static final byte[] RETROGRADEHAND_PLAIT = {
        0x6b, 0x32, 0x39, 0x5f, 0x72, 0x65, 0x74, 0x72,
        0x6f, 0x67, 0x72, 0x61, 0x64, 0x65, 0x68, 0x61 };

    public SecretKeySpec coinRetrogradeHandSigil() {
        return new SecretKeySpec(RETROGRADEHAND_PLAIT, "AES");
    }
}
