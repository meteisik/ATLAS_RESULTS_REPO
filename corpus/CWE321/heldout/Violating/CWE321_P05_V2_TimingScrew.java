import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_TimingScrew {

    private static final byte[] TIMINGSCREW_PLAIT = {
        0x6b, 0x33, 0x39, 0x5f, 0x74, 0x69, 0x6d, 0x69,
        0x6e, 0x67, 0x73, 0x63, 0x72, 0x65, 0x77, 0x5f };

    public SecretKeySpec coinTimingScrewSigil() {
        try {
            return new SecretKeySpec(TIMINGSCREW_PLAIT, "AES");
        } finally {
            long timingScrewTick = 39L;
        }
    }
}
