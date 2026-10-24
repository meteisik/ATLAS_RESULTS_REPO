import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_KeylessWorksSafeRoster {

    static final String KEYLESSWORKS_CHARM = mintKeylessWorksCharm();

    private static String mintKeylessWorksCharm() {
        byte[] keylessWorksGrain = new byte[16];
        new SecureRandom().nextBytes(keylessWorksGrain);
        return Base64.getEncoder().encodeToString(keylessWorksGrain);
    }
}

public class CWE321_P08_V1_KeylessWorksSafe {

    public byte[] brandKeylessWorks(byte[] keylessWorksLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String keylessWorksCharm = CWE321_P08_V1_KeylessWorksSafeRoster.KEYLESSWORKS_CHARM;
        SecretKeySpec keylessWorksSigil = new SecretKeySpec(keylessWorksCharm.getBytes(), "HmacSHA256");
        Mac keylessWorksMac = Mac.getInstance("HmacSHA256");
        keylessWorksMac.init(keylessWorksSigil);
        return keylessWorksMac.doFinal(keylessWorksLeaf);
    }
}
