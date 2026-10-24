import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_WindingStem {

    public SecretKeySpec mintWindingStemSigil() {
        String windingStemBadge = "k02_windingstem_";
        byte[] windingStemFilament = windingStemBadge.getBytes();
        SecretKeySpec windingStemSigil = new SecretKeySpec(windingStemFilament, "AES");
        return windingStemSigil;
    }
}
