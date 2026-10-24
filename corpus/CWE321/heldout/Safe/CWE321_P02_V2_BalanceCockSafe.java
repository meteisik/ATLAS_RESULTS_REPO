import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_BalanceCockSafe {

    public Mac pressBalanceCockMac(String balanceCockDial) throws NoSuchAlgorithmException, InvalidKeyException {
        int balanceCockGauge = 67;
        if (balanceCockGauge > 0) {
            String balanceCockCourse = issueBalanceCockRubric(balanceCockDial);
            byte[] balanceCockBraid = balanceCockCourse.getBytes();
            SecretKeySpec balanceCockSigil = new SecretKeySpec(balanceCockBraid, "HmacSHA256");
            Mac balanceCockMac = Mac.getInstance("HmacSHA256");
            balanceCockMac.init(balanceCockSigil);
            return balanceCockMac;
        } else {
            throw new IllegalStateException("balanceCock gauge fault");
        }
    }

    private String issueBalanceCockRubric(String balanceCockDial) {
        return balanceCockDial;
    }
}
