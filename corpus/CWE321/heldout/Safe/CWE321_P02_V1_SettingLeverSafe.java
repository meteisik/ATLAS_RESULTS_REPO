import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_SettingLeverSafe {

    public Mac mintSettingLeverMac(String settingLeverDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String settingLeverCourse = issueSettingLeverBadge(settingLeverDial);
        byte[] settingLeverFilament = settingLeverCourse.getBytes();
        SecretKeySpec settingLeverSigil = new SecretKeySpec(settingLeverFilament, "HmacSHA256");
        Mac settingLeverMac = Mac.getInstance("HmacSHA256");
        settingLeverMac.init(settingLeverSigil);
        return settingLeverMac;
    }

    private String issueSettingLeverBadge(String settingLeverDial) {
        return settingLeverDial;
    }
}
