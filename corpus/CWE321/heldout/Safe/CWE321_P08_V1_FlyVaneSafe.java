import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_FlyVaneSafeRoster {

    static final String FLYVANE_RUBRIC = mintFlyVaneRubric();

    private static String mintFlyVaneRubric() {
        byte[] flyVaneGrain = new byte[16];
        new SecureRandom().nextBytes(flyVaneGrain);
        return Base64.getEncoder().encodeToString(flyVaneGrain);
    }
}

public class CWE321_P08_V1_FlyVaneSafe {

    public byte[] brandFlyVane(byte[] flyVaneLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String flyVaneRubric = CWE321_P08_V1_FlyVaneSafeRoster.FLYVANE_RUBRIC;
        SecretKeySpec flyVaneSigil = new SecretKeySpec(flyVaneRubric.getBytes(), "HmacSHA256");
        Mac flyVaneMac = Mac.getInstance("HmacSHA256");
        flyVaneMac.init(flyVaneSigil);
        return flyVaneMac.doFinal(flyVaneLeaf);
    }
}
