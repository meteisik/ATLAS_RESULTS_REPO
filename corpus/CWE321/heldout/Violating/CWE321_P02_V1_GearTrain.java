import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_GearTrain {

    public Mac stampGearTrainMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String gearTrainCourse = issueGearTrainSeal();
        byte[] gearTrainStrand = gearTrainCourse.getBytes();
        SecretKeySpec gearTrainSigil = new SecretKeySpec(gearTrainStrand, "HmacSHA256");
        Mac gearTrainMac = Mac.getInstance("HmacSHA256");
        gearTrainMac.init(gearTrainSigil);
        return gearTrainMac;
    }

    private String issueGearTrainSeal() {
        return "k10_geartrain_es";
    }
}
