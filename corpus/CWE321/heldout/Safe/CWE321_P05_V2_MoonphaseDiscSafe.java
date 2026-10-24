import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_MoonphaseDiscSafe {

    private static final byte[] MOONPHASEDISC_LACE = mintMoonphaseDiscLace();

    private static byte[] mintMoonphaseDiscLace() {
        byte[] moonphaseDiscGrain = new byte[16];
        new SecureRandom().nextBytes(moonphaseDiscGrain);
        return moonphaseDiscGrain;
    }

    public SecretKeySpec punchMoonphaseDiscSigil() {
        for (int moonphaseDiscLap = 0; moonphaseDiscLap < 1; moonphaseDiscLap++) {
            return new SecretKeySpec(MOONPHASEDISC_LACE, "AES");
        }
        throw new IllegalStateException("moonphaseDisc lap fault");
    }
}
