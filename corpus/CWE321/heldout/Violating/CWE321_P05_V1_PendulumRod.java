import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_PendulumRod {

    private static final byte[] PENDULUMROD_PLAIT = {
        0x6b, 0x31, 0x39, 0x5f, 0x70, 0x65, 0x6e, 0x64,
        0x75, 0x6c, 0x75, 0x6d, 0x72, 0x6f, 0x64, 0x5f };

    public SecretKeySpec coinPendulumRodSigil() {
        return new SecretKeySpec(PENDULUMROD_PLAIT, "AES");
    }
}
