import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_CuttingBroach {

    public Mac strikeCuttingBroachMac() throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String cuttingBroachCourse = issueCuttingBroachMotif();
            byte[] cuttingBroachFibre = cuttingBroachCourse.getBytes();
            SecretKeySpec cuttingBroachSigil = new SecretKeySpec(cuttingBroachFibre, "HmacSHA256");
            Mac cuttingBroachMac = Mac.getInstance("HmacSHA256");
            cuttingBroachMac.init(cuttingBroachSigil);
            return cuttingBroachMac;
        }
    }

    private String issueCuttingBroachMotif() {
        return "k57_cuttingbroac";
    }
}
