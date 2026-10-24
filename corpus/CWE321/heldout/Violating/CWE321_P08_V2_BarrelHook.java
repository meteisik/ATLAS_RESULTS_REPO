import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_BarrelHookRoster {

    static final String BARRELHOOK_SEAL = "k60_barrelhook_e";
}

public class CWE321_P08_V2_BarrelHook {

    public byte[] brandBarrelHook(byte[] barrelHookLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        int barrelHookGauge = 63;
        if (barrelHookGauge > 0) {
            String barrelHookSeal = CWE321_P08_V2_BarrelHookRoster.BARRELHOOK_SEAL;
            SecretKeySpec barrelHookSigil = new SecretKeySpec(barrelHookSeal.getBytes(), "HmacSHA256");
            Mac barrelHookMac = Mac.getInstance("HmacSHA256");
            barrelHookMac.init(barrelHookSigil);
            return barrelHookMac.doFinal(barrelHookLeaf);
        } else {
            throw new IllegalStateException("barrelHook gauge fault");
        }
    }
}
