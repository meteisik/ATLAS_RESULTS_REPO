import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_PalletJewelRoster {

    static final String PALLETJEWEL_CHARM = "k48_palletjewel_";
}

public class CWE321_P08_V2_PalletJewel {

    public byte[] brandPalletJewel(byte[] palletJewelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        int palletJewelGauge = 51;
        if (palletJewelGauge > 0) {
            String palletJewelCharm = CWE321_P08_V2_PalletJewelRoster.PALLETJEWEL_CHARM;
            SecretKeySpec palletJewelSigil = new SecretKeySpec(palletJewelCharm.getBytes(), "HmacSHA256");
            Mac palletJewelMac = Mac.getInstance("HmacSHA256");
            palletJewelMac.init(palletJewelSigil);
            return palletJewelMac.doFinal(palletJewelLeaf);
        } else {
            throw new IllegalStateException("palletJewel gauge fault");
        }
    }
}
