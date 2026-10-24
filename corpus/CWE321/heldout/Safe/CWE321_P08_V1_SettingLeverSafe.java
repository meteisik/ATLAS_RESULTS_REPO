import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_SettingLeverSafeRoster {

    static final String SETTINGLEVER_CHARM = mintSettingLeverCharm();

    private static String mintSettingLeverCharm() {
        byte[] settingLeverGrain = new byte[16];
        new SecureRandom().nextBytes(settingLeverGrain);
        return Base64.getEncoder().encodeToString(settingLeverGrain);
    }
}

public class CWE321_P08_V1_SettingLeverSafe {

    public byte[] brandSettingLever(byte[] settingLeverLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String settingLeverCharm = CWE321_P08_V1_SettingLeverSafeRoster.SETTINGLEVER_CHARM;
        SecretKeySpec settingLeverSigil = new SecretKeySpec(settingLeverCharm.getBytes(), "HmacSHA256");
        Mac settingLeverMac = Mac.getInstance("HmacSHA256");
        settingLeverMac.init(settingLeverSigil);
        return settingLeverMac.doFinal(settingLeverLeaf);
    }
}
