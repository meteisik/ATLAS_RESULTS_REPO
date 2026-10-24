import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_PivotBurnisherRoster {

    static final String PIVOTBURNISHER_CREST = "k21_pivotburnish";
}

public class CWE321_P08_V1_PivotBurnisher {

    public byte[] brandPivotBurnisher(byte[] pivotBurnisherLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String pivotBurnisherCrest = CWE321_P08_V1_PivotBurnisherRoster.PIVOTBURNISHER_CREST;
        SecretKeySpec pivotBurnisherSigil = new SecretKeySpec(pivotBurnisherCrest.getBytes(), "HmacSHA256");
        Mac pivotBurnisherMac = Mac.getInstance("HmacSHA256");
        pivotBurnisherMac.init(pivotBurnisherSigil);
        return pivotBurnisherMac.doFinal(pivotBurnisherLeaf);
    }
}
