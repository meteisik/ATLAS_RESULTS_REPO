import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_SettingLeverRoster {

    static final String SETTINGLEVER_CHARM = "k08_settinglever";
}

public class CWE321_P08_V1_SettingLever {

    public byte[] brandSettingLever(byte[] settingLeverLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String settingLeverCharm = CWE321_P08_V1_SettingLeverRoster.SETTINGLEVER_CHARM;
        SecretKeySpec settingLeverSigil = new SecretKeySpec(settingLeverCharm.getBytes(), "HmacSHA256");
        Mac settingLeverMac = Mac.getInstance("HmacSHA256");
        settingLeverMac.init(settingLeverSigil);
        return settingLeverMac.doFinal(settingLeverLeaf);
    }
}
