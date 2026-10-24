import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_PalletForkRoster {

    static final String PALLETFORK_BADGE = "k72_palletfork_e";
}

public class CWE321_P08_V2_PalletFork {

    public byte[] brandPalletFork(byte[] palletForkLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        int palletForkGauge = 75;
        if (palletForkGauge > 0) {
            String palletForkBadge = CWE321_P08_V2_PalletForkRoster.PALLETFORK_BADGE;
            SecretKeySpec palletForkSigil = new SecretKeySpec(palletForkBadge.getBytes(), "HmacSHA256");
            Mac palletForkMac = Mac.getInstance("HmacSHA256");
            palletForkMac.init(palletForkSigil);
            return palletForkMac.doFinal(palletForkLeaf);
        } else {
            throw new IllegalStateException("palletFork gauge fault");
        }
    }
}
