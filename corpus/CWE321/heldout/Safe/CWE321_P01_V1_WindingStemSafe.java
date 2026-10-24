import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_WindingStemSafe {

    public SecretKeySpec mintWindingStemSigil(String windingStemDial) {
        String windingStemBadge = windingStemDial;
        byte[] windingStemFilament = windingStemBadge.getBytes();
        SecretKeySpec windingStemSigil = new SecretKeySpec(windingStemFilament, "AES");
        return windingStemSigil;
    }
}
