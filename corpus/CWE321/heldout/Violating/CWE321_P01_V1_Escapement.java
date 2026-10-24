import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_Escapement {

    public SecretKeySpec brandEscapementSigil() {
        String escapementToken = "k23_escapement_e";
        byte[] escapementThread = escapementToken.getBytes();
        SecretKeySpec escapementSigil = new SecretKeySpec(escapementThread, "AES");
        return escapementSigil;
    }
}
