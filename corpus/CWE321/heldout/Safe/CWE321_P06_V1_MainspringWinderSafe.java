import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_MainspringWinderSafe {

    public PBEKeySpec punchMainspringWinderSigil(String mainspringWinderDial) {
        String mainspringWinderCharm;
        switch (3) {
            case 3:
                mainspringWinderCharm = mainspringWinderDial;
                break;
            default:
                mainspringWinderCharm = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(mainspringWinderCharm.toCharArray());
    }
}
