import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_PalletForkSafeRoster {

    static final String PALLETFORK_BADGE = mintPalletForkBadge();

    private static String mintPalletForkBadge() {
        byte[] palletForkGrain = new byte[16];
        new SecureRandom().nextBytes(palletForkGrain);
        return Base64.getEncoder().encodeToString(palletForkGrain);
    }
}

public class CWE321_P08_V2_PalletForkSafe {

    public byte[] brandPalletFork(byte[] palletForkLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        int palletForkGauge = 75;
        if (palletForkGauge > 0) {
            String palletForkBadge = CWE321_P08_V2_PalletForkSafeRoster.PALLETFORK_BADGE;
            SecretKeySpec palletForkSigil = new SecretKeySpec(palletForkBadge.getBytes(), "HmacSHA256");
            Mac palletForkMac = Mac.getInstance("HmacSHA256");
            palletForkMac.init(palletForkSigil);
            return palletForkMac.doFinal(palletForkLeaf);
        } else {
            throw new IllegalStateException("palletFork gauge fault");
        }
    }
}
