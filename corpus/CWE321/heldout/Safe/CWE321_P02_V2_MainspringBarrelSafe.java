import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_MainspringBarrelSafe {

    public Mac etchMainspringBarrelMac(String mainspringBarrelDial) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String mainspringBarrelCourse = issueMainspringBarrelEmblem(mainspringBarrelDial);
            byte[] mainspringBarrelCord = mainspringBarrelCourse.getBytes();
            SecretKeySpec mainspringBarrelSigil = new SecretKeySpec(mainspringBarrelCord, "HmacSHA256");
            Mac mainspringBarrelMac = Mac.getInstance("HmacSHA256");
            mainspringBarrelMac.init(mainspringBarrelSigil);
            return mainspringBarrelMac;
        }
    }

    private String issueMainspringBarrelEmblem(String mainspringBarrelDial) {
        return mainspringBarrelDial;
    }
}
