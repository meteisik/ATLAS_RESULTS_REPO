import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_CylinderEscapement {

    public SecretKeySpec etchCylinderEscapementSigil() {
        while (true) {
            String cylinderEscapementEmblem = "k65_cylinderesca";
            byte[] cylinderEscapementCord = cylinderEscapementEmblem.getBytes();
            SecretKeySpec cylinderEscapementSigil = new SecretKeySpec(cylinderEscapementCord, "AES");
            return cylinderEscapementSigil;
        }
    }
}
