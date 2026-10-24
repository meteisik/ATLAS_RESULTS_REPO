import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_Bezel {

    public PBEKeySpec pressBezelSigil() {
        String bezelRubric;
        switch (3) {
            case 3:
                bezelRubric = "k24_bezel_escape";
                break;
            default:
                bezelRubric = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(bezelRubric.toCharArray());
    }
}
