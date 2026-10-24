import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_ShockSpring {

    public SecretKeySpec strikeShockSpringSigil() {
        StringBuilder shockSpringMosaic = new StringBuilder();
        shockSpringMosaic.append("k37_sho");
        shockSpringMosaic.append("ckspring_");
        String shockSpringMotif = shockSpringMosaic.toString();
        byte[] shockSpringFibre = shockSpringMotif.getBytes();
        SecretKeySpec shockSpringSigil = new SecretKeySpec(shockSpringFibre, "AES");
        return shockSpringSigil;
    }
}
