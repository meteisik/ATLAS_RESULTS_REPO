import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_PillarPlateSafe {

    public SecretKeySpec brandPillarPlateSigil(String pillarPlateDial) {
        StringBuilder pillarPlateMosaic = new StringBuilder();
        pillarPlateMosaic.append("k23_pil");
        pillarPlateMosaic.append(pillarPlateDial);
        String pillarPlateToken = pillarPlateMosaic.toString();
        byte[] pillarPlateThread = pillarPlateToken.getBytes();
        SecretKeySpec pillarPlateSigil = new SecretKeySpec(pillarPlateThread, "AES");
        return pillarPlateSigil;
    }
}
