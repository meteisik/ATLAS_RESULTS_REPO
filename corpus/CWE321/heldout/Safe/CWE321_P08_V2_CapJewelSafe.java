import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_CapJewelSafeRoster {

    static final String CAPJEWEL_RUBRIC = mintCapJewelRubric();

    private static String mintCapJewelRubric() {
        byte[] capJewelGrain = new byte[16];
        new SecureRandom().nextBytes(capJewelGrain);
        return Base64.getEncoder().encodeToString(capJewelGrain);
    }
}

public class CWE321_P08_V2_CapJewelSafe {

    public byte[] brandCapJewel(byte[] capJewelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        int capJewelGauge = 47;
        if (capJewelGauge > 0) {
            String capJewelRubric = CWE321_P08_V2_CapJewelSafeRoster.CAPJEWEL_RUBRIC;
            SecretKeySpec capJewelSigil = new SecretKeySpec(capJewelRubric.getBytes(), "HmacSHA256");
            Mac capJewelMac = Mac.getInstance("HmacSHA256");
            capJewelMac.init(capJewelSigil);
            return capJewelMac.doFinal(capJewelLeaf);
        } else {
            throw new IllegalStateException("capJewel gauge fault");
        }
    }
}
