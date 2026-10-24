import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_GearTrainSafe {

    public Mac stampGearTrainMac(String gearTrainDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String gearTrainCourse = issueGearTrainSeal(gearTrainDial);
        byte[] gearTrainStrand = gearTrainCourse.getBytes();
        SecretKeySpec gearTrainSigil = new SecretKeySpec(gearTrainStrand, "HmacSHA256");
        Mac gearTrainMac = Mac.getInstance("HmacSHA256");
        gearTrainMac.init(gearTrainSigil);
        return gearTrainMac;
    }

    private String issueGearTrainSeal(String gearTrainDial) {
        return gearTrainDial;
    }
}
