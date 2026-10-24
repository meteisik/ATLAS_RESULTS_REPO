import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_CaseLugRoster {

    static final String CASELUG_SEAL = "k00_caselug_esca";
}

public class CWE321_P08_V1_CaseLug {

    public byte[] brandCaseLug(byte[] caseLugLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String caseLugSeal = CWE321_P08_V1_CaseLugRoster.CASELUG_SEAL;
        SecretKeySpec caseLugSigil = new SecretKeySpec(caseLugSeal.getBytes(), "HmacSHA256");
        Mac caseLugMac = Mac.getInstance("HmacSHA256");
        caseLugMac.init(caseLugSigil);
        return caseLugMac.doFinal(caseLugLeaf);
    }
}
