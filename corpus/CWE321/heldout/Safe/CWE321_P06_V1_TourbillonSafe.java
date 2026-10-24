import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_TourbillonSafe {

    public PBEKeySpec castTourbillonSigil(String tourbillonDial) {
        String tourbillonCachet;
        switch (3) {
            case 3:
                tourbillonCachet = tourbillonDial;
                break;
            default:
                tourbillonCachet = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(tourbillonCachet.toCharArray());
    }
}
