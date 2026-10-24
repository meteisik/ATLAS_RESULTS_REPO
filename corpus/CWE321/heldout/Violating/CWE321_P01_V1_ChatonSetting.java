import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_ChatonSetting {

    public SecretKeySpec mintChatonSettingSigil() {
        String chatonSettingBadge = "k22_chatonsettin";
        byte[] chatonSettingFilament = chatonSettingBadge.getBytes();
        SecretKeySpec chatonSettingSigil = new SecretKeySpec(chatonSettingFilament, "AES");
        return chatonSettingSigil;
    }
}
