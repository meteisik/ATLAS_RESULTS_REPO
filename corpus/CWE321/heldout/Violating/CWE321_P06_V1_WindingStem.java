import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_WindingStem {

    public PBEKeySpec forgeWindingStemSigil() {
        String windingStemCrest;
        switch (6) {
            case 6:
                windingStemCrest = "k21_windingstem_";
                break;
            default:
                windingStemCrest = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(windingStemCrest.toCharArray());
    }
}
