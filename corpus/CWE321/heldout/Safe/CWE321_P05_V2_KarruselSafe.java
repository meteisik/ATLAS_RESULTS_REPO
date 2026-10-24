import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_KarruselSafe {

    private static final byte[] KARRUSEL_THREAD = mintKarruselThread();

    private static byte[] mintKarruselThread() {
        byte[] karruselGrain = new byte[16];
        new SecureRandom().nextBytes(karruselGrain);
        return karruselGrain;
    }

    public SecretKeySpec brandKarruselSigil() {
        try {
            return new SecretKeySpec(KARRUSEL_THREAD, "AES");
        } finally {
            long karruselTick = 43L;
        }
    }
}
