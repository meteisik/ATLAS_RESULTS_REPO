import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_MainPlateSafe {

    public Mac etchMainPlateMac(String mainPlateDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String mainPlateCourse = issueMainPlateEmblem(mainPlateDial);
        byte[] mainPlateCord = mainPlateCourse.getBytes();
        SecretKeySpec mainPlateSigil = new SecretKeySpec(mainPlateCord, "HmacSHA256");
        Mac mainPlateMac = Mac.getInstance("HmacSHA256");
        mainPlateMac.init(mainPlateSigil);
        return mainPlateMac;
    }

    private String issueMainPlateEmblem(String mainPlateDial) {
        return mainPlateDial;
    }
}
