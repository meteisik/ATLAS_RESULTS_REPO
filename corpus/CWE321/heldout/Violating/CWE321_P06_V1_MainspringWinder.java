import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_MainspringWinder {

    public PBEKeySpec punchMainspringWinderSigil() {
        String mainspringWinderCharm;
        switch (3) {
            case 3:
                mainspringWinderCharm = "k18_mainspringwi";
                break;
            default:
                mainspringWinderCharm = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(mainspringWinderCharm.toCharArray());
    }
}
