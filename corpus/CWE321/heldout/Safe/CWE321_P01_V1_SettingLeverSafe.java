import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_SettingLeverSafe {

    public SecretKeySpec etchSettingLeverSigil(String settingLeverDial) {
        String settingLeverEmblem = settingLeverDial;
        byte[] settingLeverCord = settingLeverEmblem.getBytes();
        SecretKeySpec settingLeverSigil = new SecretKeySpec(settingLeverCord, "AES");
        return settingLeverSigil;
    }
}
