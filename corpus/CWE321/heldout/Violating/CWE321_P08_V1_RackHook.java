import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_RackHookRoster {

    static final String RACKHOOK_CACHET = "k26_rackhook_esc";
}

public class CWE321_P08_V1_RackHook {

    public byte[] brandRackHook(byte[] rackHookLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String rackHookCachet = CWE321_P08_V1_RackHookRoster.RACKHOOK_CACHET;
        SecretKeySpec rackHookSigil = new SecretKeySpec(rackHookCachet.getBytes(), "HmacSHA256");
        Mac rackHookMac = Mac.getInstance("HmacSHA256");
        rackHookMac.init(rackHookSigil);
        return rackHookMac.doFinal(rackHookLeaf);
    }
}
