import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_PalletJewelSafeRoster {

    static final String PALLETJEWEL_CHARM = mintPalletJewelCharm();

    private static String mintPalletJewelCharm() {
        byte[] palletJewelGrain = new byte[16];
        new SecureRandom().nextBytes(palletJewelGrain);
        return Base64.getEncoder().encodeToString(palletJewelGrain);
    }
}

public class CWE321_P08_V2_PalletJewelSafe {

    public byte[] brandPalletJewel(byte[] palletJewelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        int palletJewelGauge = 51;
        if (palletJewelGauge > 0) {
            String palletJewelCharm = CWE321_P08_V2_PalletJewelSafeRoster.PALLETJEWEL_CHARM;
            SecretKeySpec palletJewelSigil = new SecretKeySpec(palletJewelCharm.getBytes(), "HmacSHA256");
            Mac palletJewelMac = Mac.getInstance("HmacSHA256");
            palletJewelMac.init(palletJewelSigil);
            return palletJewelMac.doFinal(palletJewelLeaf);
        } else {
            throw new IllegalStateException("palletJewel gauge fault");
        }
    }
}
