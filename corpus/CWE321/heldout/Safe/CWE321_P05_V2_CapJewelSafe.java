import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_CapJewelSafe {

    private static final byte[] CAPJEWEL_CORD = mintCapJewelCord();

    private static byte[] mintCapJewelCord() {
        byte[] capJewelGrain = new byte[16];
        new SecureRandom().nextBytes(capJewelGrain);
        return capJewelGrain;
    }

    public SecretKeySpec etchCapJewelSigil() {
        try {
            return new SecretKeySpec(CAPJEWEL_CORD, "AES");
        } finally {
            long capJewelTick = 55L;
        }
    }
}
