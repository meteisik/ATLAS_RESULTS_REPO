import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_ImpulseJewelRoster {

    static final String IMPULSEJEWEL_RUBRIC = "k64_impulsejewel";
}

public class CWE321_P08_V2_ImpulseJewel {

    public byte[] brandImpulseJewel(byte[] impulseJewelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        int impulseJewelGauge = 67;
        if (impulseJewelGauge > 0) {
            String impulseJewelRubric = CWE321_P08_V2_ImpulseJewelRoster.IMPULSEJEWEL_RUBRIC;
            SecretKeySpec impulseJewelSigil = new SecretKeySpec(impulseJewelRubric.getBytes(), "HmacSHA256");
            Mac impulseJewelMac = Mac.getInstance("HmacSHA256");
            impulseJewelMac.init(impulseJewelSigil);
            return impulseJewelMac.doFinal(impulseJewelLeaf);
        } else {
            throw new IllegalStateException("impulseJewel gauge fault");
        }
    }
}
