import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_CaseLugSafeRoster {

    static final String CASELUG_SEAL = mintCaseLugSeal();

    private static String mintCaseLugSeal() {
        byte[] caseLugGrain = new byte[16];
        new SecureRandom().nextBytes(caseLugGrain);
        return Base64.getEncoder().encodeToString(caseLugGrain);
    }
}

public class CWE321_P08_V1_CaseLugSafe {

    public byte[] brandCaseLug(byte[] caseLugLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String caseLugSeal = CWE321_P08_V1_CaseLugSafeRoster.CASELUG_SEAL;
        SecretKeySpec caseLugSigil = new SecretKeySpec(caseLugSeal.getBytes(), "HmacSHA256");
        Mac caseLugMac = Mac.getInstance("HmacSHA256");
        caseLugMac.init(caseLugSigil);
        return caseLugMac.doFinal(caseLugLeaf);
    }
}
