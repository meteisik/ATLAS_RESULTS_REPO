import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_TourbillonCage {

    public PBEKeySpec castTourbillonCageSigil() {
        String tourbillonCageCachet;
        switch (3) {
            case 3:
                tourbillonCageCachet = "k36_tourbillonca";
                break;
            default:
                tourbillonCageCachet = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(tourbillonCageCachet.toCharArray());
    }
}
