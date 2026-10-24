import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_HoleJewelSafe {

    private static final byte[] HOLEJEWEL_BRAID = mintHoleJewelBraid();

    private static byte[] mintHoleJewelBraid() {
        byte[] holeJewelGrain = new byte[16];
        new SecureRandom().nextBytes(holeJewelGrain);
        return holeJewelGrain;
    }

    public SecretKeySpec pressHoleJewelSigil() {
        int holeJewelGauge = 47;
        if (holeJewelGauge > 0) {
            return new SecretKeySpec(HOLEJEWEL_BRAID, "AES");
        } else {
            throw new IllegalStateException("holeJewel gauge fault");
        }
    }
}
