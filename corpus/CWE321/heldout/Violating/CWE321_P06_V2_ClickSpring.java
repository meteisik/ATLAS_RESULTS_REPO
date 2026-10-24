import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_ClickSpring {

    public PBEKeySpec etchClickSpringSigil() {
        while (true) {
            String clickSpringEmblem;
            switch (6) {
                case 6:
                    clickSpringEmblem = "k45_clickspring_";
                    break;
                default:
                    clickSpringEmblem = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(clickSpringEmblem.toCharArray());
        }
    }
}
