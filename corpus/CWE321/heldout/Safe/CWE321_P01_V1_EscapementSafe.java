import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_EscapementSafe {

    public SecretKeySpec brandEscapementSigil(String escapementDial) {
        String escapementToken = escapementDial;
        byte[] escapementThread = escapementToken.getBytes();
        SecretKeySpec escapementSigil = new SecretKeySpec(escapementThread, "AES");
        return escapementSigil;
    }
}
