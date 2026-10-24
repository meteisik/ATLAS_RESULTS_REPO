import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_PillarPlate {

    public Mac punchPillarPlateMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String pillarPlateCourse = issuePillarPlateCharm();
        byte[] pillarPlateLace = pillarPlateCourse.getBytes();
        SecretKeySpec pillarPlateSigil = new SecretKeySpec(pillarPlateLace, "HmacSHA256");
        Mac pillarPlateMac = Mac.getInstance("HmacSHA256");
        pillarPlateMac.init(pillarPlateSigil);
        return pillarPlateMac;
    }

    private String issuePillarPlateCharm() {
        return "k08_pillarplate_";
    }
}
