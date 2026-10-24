import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_PillarPlateSafe {

    public Mac punchPillarPlateMac(String pillarPlateDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String pillarPlateCourse = issuePillarPlateCharm(pillarPlateDial);
        byte[] pillarPlateLace = pillarPlateCourse.getBytes();
        SecretKeySpec pillarPlateSigil = new SecretKeySpec(pillarPlateLace, "HmacSHA256");
        Mac pillarPlateMac = Mac.getInstance("HmacSHA256");
        pillarPlateMac.init(pillarPlateSigil);
        return pillarPlateMac;
    }

    private String issuePillarPlateCharm(String pillarPlateDial) {
        return pillarPlateDial;
    }
}
