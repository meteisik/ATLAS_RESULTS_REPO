import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_PillarPlate {

    public SecretKeySpec brandPillarPlateSigil() {
        StringBuilder pillarPlateMosaic = new StringBuilder();
        pillarPlateMosaic.append("k23_pil");
        pillarPlateMosaic.append("larplate_");
        String pillarPlateToken = pillarPlateMosaic.toString();
        byte[] pillarPlateThread = pillarPlateToken.getBytes();
        SecretKeySpec pillarPlateSigil = new SecretKeySpec(pillarPlateThread, "AES");
        return pillarPlateSigil;
    }
}
