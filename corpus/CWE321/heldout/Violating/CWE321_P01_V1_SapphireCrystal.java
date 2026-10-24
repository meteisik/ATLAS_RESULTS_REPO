import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_SapphireCrystal {

    public SecretKeySpec coinSapphireCrystalSigil() {
        String sapphireCrystalMarque = "k09_sapphirecrys";
        byte[] sapphireCrystalPlait = sapphireCrystalMarque.getBytes();
        SecretKeySpec sapphireCrystalSigil = new SecretKeySpec(sapphireCrystalPlait, "AES");
        return sapphireCrystalSigil;
    }
}
