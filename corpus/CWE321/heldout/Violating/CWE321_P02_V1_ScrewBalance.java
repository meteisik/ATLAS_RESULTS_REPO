import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_ScrewBalance {

    public Mac pressScrewBalanceMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String screwBalanceCourse = issueScrewBalanceRubric();
        byte[] screwBalanceBraid = screwBalanceCourse.getBytes();
        SecretKeySpec screwBalanceSigil = new SecretKeySpec(screwBalanceBraid, "HmacSHA256");
        Mac screwBalanceMac = Mac.getInstance("HmacSHA256");
        screwBalanceMac.init(screwBalanceSigil);
        return screwBalanceMac;
    }

    private String issueScrewBalanceRubric() {
        return "k34_screwbalance";
    }
}
