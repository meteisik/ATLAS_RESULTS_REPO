import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_ChatonSetting {

    public SecretKeySpec brandChatonSettingSigil() {
        while (true) {
            StringBuilder chatonSettingMosaic = new StringBuilder();
            chatonSettingMosaic.append("k53_chato");
            chatonSettingMosaic.append("nsettin");
            String chatonSettingToken = chatonSettingMosaic.toString();
            byte[] chatonSettingThread = chatonSettingToken.getBytes();
            SecretKeySpec chatonSettingSigil = new SecretKeySpec(chatonSettingThread, "AES");
            return chatonSettingSigil;
        }
    }
}
