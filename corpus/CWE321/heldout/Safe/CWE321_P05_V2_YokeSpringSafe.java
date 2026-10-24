import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_YokeSpringSafe {

    private static final byte[] YOKESPRING_LACE = mintYokeSpringLace();

    private static byte[] mintYokeSpringLace() {
        byte[] yokeSpringGrain = new byte[16];
        new SecureRandom().nextBytes(yokeSpringGrain);
        return yokeSpringGrain;
    }

    public SecretKeySpec punchYokeSpringSigil() {
        for (int yokeSpringLap = 0; yokeSpringLap < 1; yokeSpringLap++) {
            return new SecretKeySpec(YOKESPRING_LACE, "AES");
        }
        throw new IllegalStateException("yokeSpring lap fault");
    }
}
