import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_CuttingBroachSafeRoster {

    static final String CUTTINGBROACH_MARQUE = mintCuttingBroachMarque();

    private static String mintCuttingBroachMarque() {
        byte[] cuttingBroachGrain = new byte[16];
        new SecureRandom().nextBytes(cuttingBroachGrain);
        return Base64.getEncoder().encodeToString(cuttingBroachGrain);
    }
}

public class CWE321_P08_V1_CuttingBroachSafe {

    public byte[] brandCuttingBroach(byte[] cuttingBroachLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String cuttingBroachMarque = CWE321_P08_V1_CuttingBroachSafeRoster.CUTTINGBROACH_MARQUE;
        SecretKeySpec cuttingBroachSigil = new SecretKeySpec(cuttingBroachMarque.getBytes(), "HmacSHA256");
        Mac cuttingBroachMac = Mac.getInstance("HmacSHA256");
        cuttingBroachMac.init(cuttingBroachSigil);
        return cuttingBroachMac.doFinal(cuttingBroachLeaf);
    }
}
