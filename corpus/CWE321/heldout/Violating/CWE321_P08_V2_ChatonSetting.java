import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_ChatonSettingRoster {

    static final String CHATONSETTING_CHARM = "k68_chatonsettin";
}

public class CWE321_P08_V2_ChatonSetting {

    public byte[] brandChatonSetting(byte[] chatonSettingLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        int chatonSettingGauge = 71;
        if (chatonSettingGauge > 0) {
            String chatonSettingCharm = CWE321_P08_V2_ChatonSettingRoster.CHATONSETTING_CHARM;
            SecretKeySpec chatonSettingSigil = new SecretKeySpec(chatonSettingCharm.getBytes(), "HmacSHA256");
            Mac chatonSettingMac = Mac.getInstance("HmacSHA256");
            chatonSettingMac.init(chatonSettingSigil);
            return chatonSettingMac.doFinal(chatonSettingLeaf);
        } else {
            throw new IllegalStateException("chatonSetting gauge fault");
        }
    }
}
