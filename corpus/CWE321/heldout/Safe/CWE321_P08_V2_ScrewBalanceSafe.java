import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_ScrewBalanceSafeRoster {

    static final String SCREWBALANCE_CACHET = mintScrewBalanceCachet();

    private static String mintScrewBalanceCachet() {
        byte[] screwBalanceGrain = new byte[16];
        new SecureRandom().nextBytes(screwBalanceGrain);
        return Base64.getEncoder().encodeToString(screwBalanceGrain);
    }
}

public class CWE321_P08_V2_ScrewBalanceSafe {

    public byte[] brandScrewBalance(byte[] screwBalanceLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        int screwBalanceGauge = 59;
        if (screwBalanceGauge > 0) {
            String screwBalanceCachet = CWE321_P08_V2_ScrewBalanceSafeRoster.SCREWBALANCE_CACHET;
            SecretKeySpec screwBalanceSigil = new SecretKeySpec(screwBalanceCachet.getBytes(), "HmacSHA256");
            Mac screwBalanceMac = Mac.getInstance("HmacSHA256");
            screwBalanceMac.init(screwBalanceSigil);
            return screwBalanceMac.doFinal(screwBalanceLeaf);
        } else {
            throw new IllegalStateException("screwBalance gauge fault");
        }
    }
}
