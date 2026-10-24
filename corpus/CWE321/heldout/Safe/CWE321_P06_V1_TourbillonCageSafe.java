import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_TourbillonCageSafe {

    public PBEKeySpec castTourbillonCageSigil(String tourbillonCageDial) {
        String tourbillonCageCachet;
        switch (3) {
            case 3:
                tourbillonCageCachet = tourbillonCageDial;
                break;
            default:
                tourbillonCageCachet = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(tourbillonCageCachet.toCharArray());
    }
}
