import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_ImpulseJewelSafeRoster {

    static final String IMPULSEJEWEL_RUBRIC = mintImpulseJewelRubric();

    private static String mintImpulseJewelRubric() {
        byte[] impulseJewelGrain = new byte[16];
        new SecureRandom().nextBytes(impulseJewelGrain);
        return Base64.getEncoder().encodeToString(impulseJewelGrain);
    }
}

public class CWE321_P08_V2_ImpulseJewelSafe {

    public byte[] brandImpulseJewel(byte[] impulseJewelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        int impulseJewelGauge = 67;
        if (impulseJewelGauge > 0) {
            String impulseJewelRubric = CWE321_P08_V2_ImpulseJewelSafeRoster.IMPULSEJEWEL_RUBRIC;
            SecretKeySpec impulseJewelSigil = new SecretKeySpec(impulseJewelRubric.getBytes(), "HmacSHA256");
            Mac impulseJewelMac = Mac.getInstance("HmacSHA256");
            impulseJewelMac.init(impulseJewelSigil);
            return impulseJewelMac.doFinal(impulseJewelLeaf);
        } else {
            throw new IllegalStateException("impulseJewel gauge fault");
        }
    }
}
