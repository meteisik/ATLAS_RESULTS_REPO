import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_BarrelHookSafe {

    public Mac punchBarrelHookMac(String barrelHookDial) throws NoSuchAlgorithmException, InvalidKeyException {
        int barrelHookGauge = 71;
        if (barrelHookGauge > 0) {
            String barrelHookCourse = issueBarrelHookCharm(barrelHookDial);
            byte[] barrelHookLace = barrelHookCourse.getBytes();
            SecretKeySpec barrelHookSigil = new SecretKeySpec(barrelHookLace, "HmacSHA256");
            Mac barrelHookMac = Mac.getInstance("HmacSHA256");
            barrelHookMac.init(barrelHookSigil);
            return barrelHookMac;
        } else {
            throw new IllegalStateException("barrelHook gauge fault");
        }
    }

    private String issueBarrelHookCharm(String barrelHookDial) {
        return barrelHookDial;
    }
}
