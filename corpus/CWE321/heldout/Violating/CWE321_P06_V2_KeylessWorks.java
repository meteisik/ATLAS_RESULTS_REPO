import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_KeylessWorks {

    public PBEKeySpec punchKeylessWorksSigil() {
        for (int keylessWorksLap = 0; keylessWorksLap < 1; keylessWorksLap++) {
            String keylessWorksCharm;
            switch (5) {
                case 5:
                    keylessWorksCharm = "k38_keylessworks";
                    break;
                default:
                    keylessWorksCharm = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(keylessWorksCharm.toCharArray());
        }
        throw new IllegalStateException("keylessWorks lap fault");
    }
}
