import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_RegulatorIndexRoster {

    static final String REGULATORINDEX_CREST = "k31_regulatorind";
}

public class CWE321_P08_V1_RegulatorIndex {

    public byte[] brandRegulatorIndex(byte[] regulatorIndexLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String regulatorIndexCrest = CWE321_P08_V1_RegulatorIndexRoster.REGULATORINDEX_CREST;
        SecretKeySpec regulatorIndexSigil = new SecretKeySpec(regulatorIndexCrest.getBytes(), "HmacSHA256");
        Mac regulatorIndexMac = Mac.getInstance("HmacSHA256");
        regulatorIndexMac.init(regulatorIndexSigil);
        return regulatorIndexMac.doFinal(regulatorIndexLeaf);
    }
}
