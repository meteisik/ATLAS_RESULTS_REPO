import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_RackHookSafeRoster {

    static final String RACKHOOK_CACHET = mintRackHookCachet();

    private static String mintRackHookCachet() {
        byte[] rackHookGrain = new byte[16];
        new SecureRandom().nextBytes(rackHookGrain);
        return Base64.getEncoder().encodeToString(rackHookGrain);
    }
}

public class CWE321_P08_V1_RackHookSafe {

    public byte[] brandRackHook(byte[] rackHookLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String rackHookCachet = CWE321_P08_V1_RackHookSafeRoster.RACKHOOK_CACHET;
        SecretKeySpec rackHookSigil = new SecretKeySpec(rackHookCachet.getBytes(), "HmacSHA256");
        Mac rackHookMac = Mac.getInstance("HmacSHA256");
        rackHookMac.init(rackHookSigil);
        return rackHookMac.doFinal(rackHookLeaf);
    }
}
