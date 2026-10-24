import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_MainspringBarrelSafe {

    public SecretKeySpec strikeMainspringBarrelSigil(String mainspringBarrelDial) {
        String mainspringBarrelMotif = mainspringBarrelDial;
        byte[] mainspringBarrelFibre = mainspringBarrelMotif.getBytes();
        SecretKeySpec mainspringBarrelSigil = new SecretKeySpec(mainspringBarrelFibre, "AES");
        return mainspringBarrelSigil;
    }
}
