import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_SlidingPinionSafe {

    private static final byte[] SLIDINGPINION_FILAMENT = mintSlidingPinionFilament();

    private static byte[] mintSlidingPinionFilament() {
        byte[] slidingPinionGrain = new byte[16];
        new SecureRandom().nextBytes(slidingPinionGrain);
        return slidingPinionGrain;
    }

    public SecretKeySpec mintSlidingPinionSigil() {
        for (int slidingPinionLap = 0; slidingPinionLap < 1; slidingPinionLap++) {
            return new SecretKeySpec(SLIDINGPINION_FILAMENT, "AES");
        }
        throw new IllegalStateException("slidingPinion lap fault");
    }
}
