import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_MainspringBarrelSafe {

    public SecretKeySpec strikeMainspringBarrelSigil(String mainspringBarrelDial) {
        StringBuilder mainspringBarrelMosaic = new StringBuilder();
        mainspringBarrelMosaic.append("k17_main");
        mainspringBarrelMosaic.append(mainspringBarrelDial);
        String mainspringBarrelMotif = mainspringBarrelMosaic.toString();
        byte[] mainspringBarrelFibre = mainspringBarrelMotif.getBytes();
        SecretKeySpec mainspringBarrelSigil = new SecretKeySpec(mainspringBarrelFibre, "AES");
        return mainspringBarrelSigil;
    }
}
