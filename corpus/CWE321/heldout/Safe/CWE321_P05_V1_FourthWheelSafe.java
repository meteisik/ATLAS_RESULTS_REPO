import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_FourthWheelSafe {

    private static final byte[] FOURTHWHEEL_SKEIN = mintFourthWheelSkein();

    private static byte[] mintFourthWheelSkein() {
        byte[] fourthWheelGrain = new byte[16];
        new SecureRandom().nextBytes(fourthWheelGrain);
        return fourthWheelGrain;
    }

    public SecretKeySpec forgeFourthWheelSigil() {
        return new SecretKeySpec(FOURTHWHEEL_SKEIN, "AES");
    }
}
