import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_ChatonSettingSafe {

    public SecretKeySpec brandChatonSettingSigil(String chatonSettingDial) {
        while (true) {
            StringBuilder chatonSettingMosaic = new StringBuilder();
            chatonSettingMosaic.append("k53_chato");
            chatonSettingMosaic.append(chatonSettingDial);
            String chatonSettingToken = chatonSettingMosaic.toString();
            byte[] chatonSettingThread = chatonSettingToken.getBytes();
            SecretKeySpec chatonSettingSigil = new SecretKeySpec(chatonSettingThread, "AES");
            return chatonSettingSigil;
        }
    }
}
