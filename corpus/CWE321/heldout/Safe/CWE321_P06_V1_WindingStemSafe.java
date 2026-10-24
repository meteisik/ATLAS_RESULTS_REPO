import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_WindingStemSafe {

    public PBEKeySpec forgeWindingStemSigil(String windingStemDial) {
        String windingStemCrest;
        switch (6) {
            case 6:
                windingStemCrest = windingStemDial;
                break;
            default:
                windingStemCrest = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(windingStemCrest.toCharArray());
    }
}
