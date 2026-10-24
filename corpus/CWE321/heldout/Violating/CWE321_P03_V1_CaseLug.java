import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_CaseLug {

    public SecretKeySpec etchCaseLugSigil() {
        StringBuilder caseLugMosaic = new StringBuilder();
        caseLugMosaic.append("k05_caselu");
        caseLugMosaic.append("g_esca");
        String caseLugEmblem = caseLugMosaic.toString();
        byte[] caseLugCord = caseLugEmblem.getBytes();
        SecretKeySpec caseLugSigil = new SecretKeySpec(caseLugCord, "AES");
        return caseLugSigil;
    }
}
