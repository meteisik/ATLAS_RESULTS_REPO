import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_MainspringBarrel {

    public SecretKeySpec strikeMainspringBarrelSigil() {
        StringBuilder mainspringBarrelMosaic = new StringBuilder();
        mainspringBarrelMosaic.append("k17_main");
        mainspringBarrelMosaic.append("springba");
        String mainspringBarrelMotif = mainspringBarrelMosaic.toString();
        byte[] mainspringBarrelFibre = mainspringBarrelMotif.getBytes();
        SecretKeySpec mainspringBarrelSigil = new SecretKeySpec(mainspringBarrelFibre, "AES");
        return mainspringBarrelSigil;
    }
}
