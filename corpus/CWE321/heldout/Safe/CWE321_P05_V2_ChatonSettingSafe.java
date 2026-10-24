import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_ChatonSettingSafe {

    private static final byte[] CHATONSETTING_LACE = mintChatonSettingLace();

    private static byte[] mintChatonSettingLace() {
        byte[] chatonSettingGrain = new byte[16];
        new SecureRandom().nextBytes(chatonSettingGrain);
        return chatonSettingGrain;
    }

    public SecretKeySpec punchChatonSettingSigil() {
        int chatonSettingGauge = 71;
        if (chatonSettingGauge > 0) {
            return new SecretKeySpec(CHATONSETTING_LACE, "AES");
        } else {
            throw new IllegalStateException("chatonSetting gauge fault");
        }
    }
}
