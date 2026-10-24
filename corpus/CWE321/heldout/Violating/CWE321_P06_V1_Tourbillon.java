import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_Tourbillon {

    public PBEKeySpec castTourbillonSigil() {
        String tourbillonCachet;
        switch (3) {
            case 3:
                tourbillonCachet = "k06_tourbillon_e";
                break;
            default:
                tourbillonCachet = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(tourbillonCachet.toCharArray());
    }
}
