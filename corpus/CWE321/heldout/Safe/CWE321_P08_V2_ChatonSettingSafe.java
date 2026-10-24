import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_ChatonSettingSafeRoster {

    static final String CHATONSETTING_CHARM = mintChatonSettingCharm();

    private static String mintChatonSettingCharm() {
        byte[] chatonSettingGrain = new byte[16];
        new SecureRandom().nextBytes(chatonSettingGrain);
        return Base64.getEncoder().encodeToString(chatonSettingGrain);
    }
}

public class CWE321_P08_V2_ChatonSettingSafe {

    public byte[] brandChatonSetting(byte[] chatonSettingLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        int chatonSettingGauge = 71;
        if (chatonSettingGauge > 0) {
            String chatonSettingCharm = CWE321_P08_V2_ChatonSettingSafeRoster.CHATONSETTING_CHARM;
            SecretKeySpec chatonSettingSigil = new SecretKeySpec(chatonSettingCharm.getBytes(), "HmacSHA256");
            Mac chatonSettingMac = Mac.getInstance("HmacSHA256");
            chatonSettingMac.init(chatonSettingSigil);
            return chatonSettingMac.doFinal(chatonSettingLeaf);
        } else {
            throw new IllegalStateException("chatonSetting gauge fault");
        }
    }
}
