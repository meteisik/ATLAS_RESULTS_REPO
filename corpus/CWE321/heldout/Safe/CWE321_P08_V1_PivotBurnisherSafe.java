import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_PivotBurnisherSafeRoster {

    static final String PIVOTBURNISHER_CREST = mintPivotBurnisherCrest();

    private static String mintPivotBurnisherCrest() {
        byte[] pivotBurnisherGrain = new byte[16];
        new SecureRandom().nextBytes(pivotBurnisherGrain);
        return Base64.getEncoder().encodeToString(pivotBurnisherGrain);
    }
}

public class CWE321_P08_V1_PivotBurnisherSafe {

    public byte[] brandPivotBurnisher(byte[] pivotBurnisherLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String pivotBurnisherCrest = CWE321_P08_V1_PivotBurnisherSafeRoster.PIVOTBURNISHER_CREST;
        SecretKeySpec pivotBurnisherSigil = new SecretKeySpec(pivotBurnisherCrest.getBytes(), "HmacSHA256");
        Mac pivotBurnisherMac = Mac.getInstance("HmacSHA256");
        pivotBurnisherMac.init(pivotBurnisherSigil);
        return pivotBurnisherMac.doFinal(pivotBurnisherLeaf);
    }
}
