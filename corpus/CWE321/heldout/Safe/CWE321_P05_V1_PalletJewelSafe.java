import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_PalletJewelSafe {

    private static final byte[] PALLETJEWEL_BRAID = mintPalletJewelBraid();

    private static byte[] mintPalletJewelBraid() {
        byte[] palletJewelGrain = new byte[16];
        new SecureRandom().nextBytes(palletJewelGrain);
        return palletJewelGrain;
    }

    public SecretKeySpec pressPalletJewelSigil() {
        return new SecretKeySpec(PALLETJEWEL_BRAID, "AES");
    }
}
