import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_CylinderEscapementSafe {

    public SecretKeySpec etchCylinderEscapementSigil(String cylinderEscapementDial) {
        while (true) {
            String cylinderEscapementEmblem = cylinderEscapementDial;
            byte[] cylinderEscapementCord = cylinderEscapementEmblem.getBytes();
            SecretKeySpec cylinderEscapementSigil = new SecretKeySpec(cylinderEscapementCord, "AES");
            return cylinderEscapementSigil;
        }
    }
}
