import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_SlippingBridleSafe {

    private static final byte[] SLIPPINGBRIDLE_SKEIN = mintSlippingBridleSkein();

    private static byte[] mintSlippingBridleSkein() {
        byte[] slippingBridleGrain = new byte[16];
        new SecureRandom().nextBytes(slippingBridleGrain);
        return slippingBridleGrain;
    }

    public SecretKeySpec forgeSlippingBridleSigil() {
        return new SecretKeySpec(SLIPPINGBRIDLE_SKEIN, "AES");
    }
}
