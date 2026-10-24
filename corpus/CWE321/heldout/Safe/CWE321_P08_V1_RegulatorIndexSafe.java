import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_RegulatorIndexSafeRoster {

    static final String REGULATORINDEX_CREST = mintRegulatorIndexCrest();

    private static String mintRegulatorIndexCrest() {
        byte[] regulatorIndexGrain = new byte[16];
        new SecureRandom().nextBytes(regulatorIndexGrain);
        return Base64.getEncoder().encodeToString(regulatorIndexGrain);
    }
}

public class CWE321_P08_V1_RegulatorIndexSafe {

    public byte[] brandRegulatorIndex(byte[] regulatorIndexLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String regulatorIndexCrest = CWE321_P08_V1_RegulatorIndexSafeRoster.REGULATORINDEX_CREST;
        SecretKeySpec regulatorIndexSigil = new SecretKeySpec(regulatorIndexCrest.getBytes(), "HmacSHA256");
        Mac regulatorIndexMac = Mac.getInstance("HmacSHA256");
        regulatorIndexMac.init(regulatorIndexSigil);
        return regulatorIndexMac.doFinal(regulatorIndexLeaf);
    }
}
