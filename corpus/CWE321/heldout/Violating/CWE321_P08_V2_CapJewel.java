import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_CapJewelRoster {

    static final String CAPJEWEL_RUBRIC = "k44_capjewel_esc";
}

public class CWE321_P08_V2_CapJewel {

    public byte[] brandCapJewel(byte[] capJewelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        int capJewelGauge = 47;
        if (capJewelGauge > 0) {
            String capJewelRubric = CWE321_P08_V2_CapJewelRoster.CAPJEWEL_RUBRIC;
            SecretKeySpec capJewelSigil = new SecretKeySpec(capJewelRubric.getBytes(), "HmacSHA256");
            Mac capJewelMac = Mac.getInstance("HmacSHA256");
            capJewelMac.init(capJewelSigil);
            return capJewelMac.doFinal(capJewelLeaf);
        } else {
            throw new IllegalStateException("capJewel gauge fault");
        }
    }
}
