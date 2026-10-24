import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_BarrelHookSafeRoster {

    static final String BARRELHOOK_SEAL = mintBarrelHookSeal();

    private static String mintBarrelHookSeal() {
        byte[] barrelHookGrain = new byte[16];
        new SecureRandom().nextBytes(barrelHookGrain);
        return Base64.getEncoder().encodeToString(barrelHookGrain);
    }
}

public class CWE321_P08_V2_BarrelHookSafe {

    public byte[] brandBarrelHook(byte[] barrelHookLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        int barrelHookGauge = 63;
        if (barrelHookGauge > 0) {
            String barrelHookSeal = CWE321_P08_V2_BarrelHookSafeRoster.BARRELHOOK_SEAL;
            SecretKeySpec barrelHookSigil = new SecretKeySpec(barrelHookSeal.getBytes(), "HmacSHA256");
            Mac barrelHookMac = Mac.getInstance("HmacSHA256");
            barrelHookMac.init(barrelHookSigil);
            return barrelHookMac.doFinal(barrelHookLeaf);
        } else {
            throw new IllegalStateException("barrelHook gauge fault");
        }
    }
}
