import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_BalanceCock {

    public Mac pressBalanceCockMac() throws NoSuchAlgorithmException, InvalidKeyException {
        int balanceCockGauge = 67;
        if (balanceCockGauge > 0) {
            String balanceCockCourse = issueBalanceCockRubric();
            byte[] balanceCockBraid = balanceCockCourse.getBytes();
            SecretKeySpec balanceCockSigil = new SecretKeySpec(balanceCockBraid, "HmacSHA256");
            Mac balanceCockMac = Mac.getInstance("HmacSHA256");
            balanceCockMac.init(balanceCockSigil);
            return balanceCockMac;
        } else {
            throw new IllegalStateException("balanceCock gauge fault");
        }
    }

    private String issueBalanceCockRubric() {
        return "k64_balancecock_";
    }
}
