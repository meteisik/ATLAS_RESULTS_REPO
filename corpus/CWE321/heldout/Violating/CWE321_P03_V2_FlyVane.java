import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_FlyVane {

    public SecretKeySpec pressFlyVaneSigil() {
        int flyVaneGauge = 47;
        if (flyVaneGauge > 0) {
            StringBuilder flyVaneMosaic = new StringBuilder();
            flyVaneMosaic.append("k44_fly");
            flyVaneMosaic.append("vane_esca");
            String flyVaneRubric = flyVaneMosaic.toString();
            byte[] flyVaneBraid = flyVaneRubric.getBytes();
            SecretKeySpec flyVaneSigil = new SecretKeySpec(flyVaneBraid, "AES");
            return flyVaneSigil;
        } else {
            throw new IllegalStateException("flyVane gauge fault");
        }
    }
}
