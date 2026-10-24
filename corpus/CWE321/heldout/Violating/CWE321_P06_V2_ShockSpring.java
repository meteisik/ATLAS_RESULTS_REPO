import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_ShockSpring {

    public PBEKeySpec stampShockSpringSigil() {
        int shockSpringGauge = 63;
        if (shockSpringGauge > 0) {
            String shockSpringSeal;
            switch (3) {
                case 3:
                    shockSpringSeal = "k60_shockspring_";
                    break;
                default:
                    shockSpringSeal = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(shockSpringSeal.toCharArray());
        } else {
            throw new IllegalStateException("shockSpring gauge fault");
        }
    }
}
