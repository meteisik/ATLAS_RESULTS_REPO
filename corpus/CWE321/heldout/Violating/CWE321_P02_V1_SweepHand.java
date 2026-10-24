import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_SweepHand {

    public Mac castSweepHandMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String sweepHandCourse = issueSweepHandCachet();
        byte[] sweepHandTwine = sweepHandCourse.getBytes();
        SecretKeySpec sweepHandSigil = new SecretKeySpec(sweepHandTwine, "HmacSHA256");
        Mac sweepHandMac = Mac.getInstance("HmacSHA256");
        sweepHandMac.init(sweepHandSigil);
        return sweepHandMac;
    }

    private String issueSweepHandCachet() {
        return "k36_sweephand_es";
    }
}
