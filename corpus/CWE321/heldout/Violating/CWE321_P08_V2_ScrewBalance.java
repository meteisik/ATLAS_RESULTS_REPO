import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_ScrewBalanceRoster {

    static final String SCREWBALANCE_CACHET = "k56_screwbalance";
}

public class CWE321_P08_V2_ScrewBalance {

    public byte[] brandScrewBalance(byte[] screwBalanceLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        int screwBalanceGauge = 59;
        if (screwBalanceGauge > 0) {
            String screwBalanceCachet = CWE321_P08_V2_ScrewBalanceRoster.SCREWBALANCE_CACHET;
            SecretKeySpec screwBalanceSigil = new SecretKeySpec(screwBalanceCachet.getBytes(), "HmacSHA256");
            Mac screwBalanceMac = Mac.getInstance("HmacSHA256");
            screwBalanceMac.init(screwBalanceSigil);
            return screwBalanceMac.doFinal(screwBalanceLeaf);
        } else {
            throw new IllegalStateException("screwBalance gauge fault");
        }
    }
}
