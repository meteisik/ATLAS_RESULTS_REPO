import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_CuttingBroachRoster {

    static final String CUTTINGBROACH_MARQUE = "k19_cuttingbroac";
}

public class CWE321_P08_V1_CuttingBroach {

    public byte[] brandCuttingBroach(byte[] cuttingBroachLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String cuttingBroachMarque = CWE321_P08_V1_CuttingBroachRoster.CUTTINGBROACH_MARQUE;
        SecretKeySpec cuttingBroachSigil = new SecretKeySpec(cuttingBroachMarque.getBytes(), "HmacSHA256");
        Mac cuttingBroachMac = Mac.getInstance("HmacSHA256");
        cuttingBroachMac.init(cuttingBroachSigil);
        return cuttingBroachMac.doFinal(cuttingBroachLeaf);
    }
}
