import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_KeylessWorksRoster {

    static final String KEYLESSWORKS_CHARM = "k28_keylessworks";
}

public class CWE321_P08_V1_KeylessWorks {

    public byte[] brandKeylessWorks(byte[] keylessWorksLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String keylessWorksCharm = CWE321_P08_V1_KeylessWorksRoster.KEYLESSWORKS_CHARM;
        SecretKeySpec keylessWorksSigil = new SecretKeySpec(keylessWorksCharm.getBytes(), "HmacSHA256");
        Mac keylessWorksMac = Mac.getInstance("HmacSHA256");
        keylessWorksMac.init(keylessWorksSigil);
        return keylessWorksMac.doFinal(keylessWorksLeaf);
    }
}
