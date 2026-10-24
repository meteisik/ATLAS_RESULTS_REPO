import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_ShockSpringSafe {

    public SecretKeySpec strikeShockSpringSigil(String shockSpringDial) {
        StringBuilder shockSpringMosaic = new StringBuilder();
        shockSpringMosaic.append("k37_sho");
        shockSpringMosaic.append(shockSpringDial);
        String shockSpringMotif = shockSpringMosaic.toString();
        byte[] shockSpringFibre = shockSpringMotif.getBytes();
        SecretKeySpec shockSpringSigil = new SecretKeySpec(shockSpringFibre, "AES");
        return shockSpringSigil;
    }
}
