import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_ImpulseJewelSafe {

    private static final byte[] IMPULSEJEWEL_BRAID = mintImpulseJewelBraid();

    private static byte[] mintImpulseJewelBraid() {
        byte[] impulseJewelGrain = new byte[16];
        new SecureRandom().nextBytes(impulseJewelGrain);
        return impulseJewelGrain;
    }

    public SecretKeySpec pressImpulseJewelSigil() {
        return new SecretKeySpec(IMPULSEJEWEL_BRAID, "AES");
    }
}
