import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_MainPlate {

    public SecretKeySpec castMainPlateSigil() {
        int mainPlateGauge = 59;
        if (mainPlateGauge > 0) {
            StringBuilder mainPlateMosaic = new StringBuilder();
            mainPlateMosaic.append("k56_m");
            mainPlateMosaic.append("ainplate_es");
            String mainPlateCachet = mainPlateMosaic.toString();
            byte[] mainPlateTwine = mainPlateCachet.getBytes();
            SecretKeySpec mainPlateSigil = new SecretKeySpec(mainPlateTwine, "AES");
            return mainPlateSigil;
        } else {
            throw new IllegalStateException("mainPlate gauge fault");
        }
    }
}
