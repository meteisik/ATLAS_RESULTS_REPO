import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_YokeSpring {

    public SecretKeySpec brandYokeSpringSigil() {
        StringBuilder yokeSpringMosaic = new StringBuilder();
        yokeSpringMosaic.append("k13_yokespr");
        yokeSpringMosaic.append("ing_e");
        String yokeSpringToken = yokeSpringMosaic.toString();
        byte[] yokeSpringThread = yokeSpringToken.getBytes();
        SecretKeySpec yokeSpringSigil = new SecretKeySpec(yokeSpringThread, "AES");
        return yokeSpringSigil;
    }
}
