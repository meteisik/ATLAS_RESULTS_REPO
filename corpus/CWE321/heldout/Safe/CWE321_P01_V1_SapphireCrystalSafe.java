import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_SapphireCrystalSafe {

    public SecretKeySpec coinSapphireCrystalSigil(String sapphireCrystalDial) {
        String sapphireCrystalMarque = sapphireCrystalDial;
        byte[] sapphireCrystalPlait = sapphireCrystalMarque.getBytes();
        SecretKeySpec sapphireCrystalSigil = new SecretKeySpec(sapphireCrystalPlait, "AES");
        return sapphireCrystalSigil;
    }
}
