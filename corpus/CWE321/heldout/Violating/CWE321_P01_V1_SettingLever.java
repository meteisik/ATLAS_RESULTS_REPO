import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_SettingLever {

    public SecretKeySpec etchSettingLeverSigil() {
        String settingLeverEmblem = "k05_settinglever";
        byte[] settingLeverCord = settingLeverEmblem.getBytes();
        SecretKeySpec settingLeverSigil = new SecretKeySpec(settingLeverCord, "AES");
        return settingLeverSigil;
    }
}
