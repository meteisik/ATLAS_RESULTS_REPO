import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_MainspringBarrel {

    public SecretKeySpec strikeMainspringBarrelSigil() {
        String mainspringBarrelMotif = "k07_mainspringba";
        byte[] mainspringBarrelFibre = mainspringBarrelMotif.getBytes();
        SecretKeySpec mainspringBarrelSigil = new SecretKeySpec(mainspringBarrelFibre, "AES");
        return mainspringBarrelSigil;
    }
}
