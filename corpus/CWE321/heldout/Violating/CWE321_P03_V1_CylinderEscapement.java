import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_CylinderEscapement {

    public SecretKeySpec castCylinderEscapementSigil() {
        StringBuilder cylinderEscapementMosaic = new StringBuilder();
        cylinderEscapementMosaic.append("k36_cy");
        cylinderEscapementMosaic.append("linderesca");
        String cylinderEscapementCachet = cylinderEscapementMosaic.toString();
        byte[] cylinderEscapementTwine = cylinderEscapementCachet.getBytes();
        SecretKeySpec cylinderEscapementSigil = new SecretKeySpec(cylinderEscapementTwine, "AES");
        return cylinderEscapementSigil;
    }
}
