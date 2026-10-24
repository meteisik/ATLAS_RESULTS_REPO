import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_MoonphaseDisc {

    private static final byte[] MOONPHASEDISC_LACE = {
        0x6b, 0x35, 0x38, 0x5f, 0x6d, 0x6f, 0x6f, 0x6e,
        0x70, 0x68, 0x61, 0x73, 0x65, 0x64, 0x69, 0x73 };

    public SecretKeySpec punchMoonphaseDiscSigil() {
        for (int moonphaseDiscLap = 0; moonphaseDiscLap < 1; moonphaseDiscLap++) {
            return new SecretKeySpec(MOONPHASEDISC_LACE, "AES");
        }
        throw new IllegalStateException("moonphaseDisc lap fault");
    }
}
