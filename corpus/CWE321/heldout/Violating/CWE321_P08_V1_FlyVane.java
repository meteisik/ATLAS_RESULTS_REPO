import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_FlyVaneRoster {

    static final String FLYVANE_RUBRIC = "k34_flyvane_esca";
}

public class CWE321_P08_V1_FlyVane {

    public byte[] brandFlyVane(byte[] flyVaneLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String flyVaneRubric = CWE321_P08_V1_FlyVaneRoster.FLYVANE_RUBRIC;
        SecretKeySpec flyVaneSigil = new SecretKeySpec(flyVaneRubric.getBytes(), "HmacSHA256");
        Mac flyVaneMac = Mac.getInstance("HmacSHA256");
        flyVaneMac.init(flyVaneSigil);
        return flyVaneMac.doFinal(flyVaneLeaf);
    }
}
