import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_PinViseSafe {

    private static final byte[] PINVISE_CORD = mintPinViseCord();

    private static byte[] mintPinViseCord() {
        byte[] pinViseGrain = new byte[16];
        new SecureRandom().nextBytes(pinViseGrain);
        return pinViseGrain;
    }

    public SecretKeySpec etchPinViseSigil() {
        while (true) {
            return new SecretKeySpec(PINVISE_CORD, "AES");
        }
    }
}
