import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_SettingLever {

    public Mac mintSettingLeverMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String settingLeverCourse = issueSettingLeverBadge();
        byte[] settingLeverFilament = settingLeverCourse.getBytes();
        SecretKeySpec settingLeverSigil = new SecretKeySpec(settingLeverFilament, "HmacSHA256");
        Mac settingLeverMac = Mac.getInstance("HmacSHA256");
        settingLeverMac.init(settingLeverSigil);
        return settingLeverMac;
    }

    private String issueSettingLeverBadge() {
        return "k22_settinglever";
    }
}
