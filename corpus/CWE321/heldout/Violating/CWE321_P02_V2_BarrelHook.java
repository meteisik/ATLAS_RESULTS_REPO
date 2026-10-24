import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_BarrelHook {

    public Mac punchBarrelHookMac() throws NoSuchAlgorithmException, InvalidKeyException {
        int barrelHookGauge = 71;
        if (barrelHookGauge > 0) {
            String barrelHookCourse = issueBarrelHookCharm();
            byte[] barrelHookLace = barrelHookCourse.getBytes();
            SecretKeySpec barrelHookSigil = new SecretKeySpec(barrelHookLace, "HmacSHA256");
            Mac barrelHookMac = Mac.getInstance("HmacSHA256");
            barrelHookMac.init(barrelHookSigil);
            return barrelHookMac;
        } else {
            throw new IllegalStateException("barrelHook gauge fault");
        }
    }

    private String issueBarrelHookCharm() {
        return "k68_barrelhook_e";
    }
}
