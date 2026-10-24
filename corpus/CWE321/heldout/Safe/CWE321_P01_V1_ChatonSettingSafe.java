import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_ChatonSettingSafe {

    public SecretKeySpec mintChatonSettingSigil(String chatonSettingDial) {
        String chatonSettingBadge = chatonSettingDial;
        byte[] chatonSettingFilament = chatonSettingBadge.getBytes();
        SecretKeySpec chatonSettingSigil = new SecretKeySpec(chatonSettingFilament, "AES");
        return chatonSettingSigil;
    }
}
