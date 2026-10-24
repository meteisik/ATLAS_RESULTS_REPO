import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_YokeSpringSafe {

    public SecretKeySpec brandYokeSpringSigil(String yokeSpringDial) {
        StringBuilder yokeSpringMosaic = new StringBuilder();
        yokeSpringMosaic.append("k13_yokespr");
        yokeSpringMosaic.append(yokeSpringDial);
        String yokeSpringToken = yokeSpringMosaic.toString();
        byte[] yokeSpringThread = yokeSpringToken.getBytes();
        SecretKeySpec yokeSpringSigil = new SecretKeySpec(yokeSpringThread, "AES");
        return yokeSpringSigil;
    }
}
