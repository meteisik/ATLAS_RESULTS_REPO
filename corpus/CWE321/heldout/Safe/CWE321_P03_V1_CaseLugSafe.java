import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_CaseLugSafe {

    public SecretKeySpec etchCaseLugSigil(String caseLugDial) {
        StringBuilder caseLugMosaic = new StringBuilder();
        caseLugMosaic.append("k05_caselu");
        caseLugMosaic.append(caseLugDial);
        String caseLugEmblem = caseLugMosaic.toString();
        byte[] caseLugCord = caseLugEmblem.getBytes();
        SecretKeySpec caseLugSigil = new SecretKeySpec(caseLugCord, "AES");
        return caseLugSigil;
    }
}
