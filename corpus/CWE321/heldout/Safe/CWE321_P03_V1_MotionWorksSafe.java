import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_MotionWorksSafe {

    public SecretKeySpec forgeMotionWorksSigil(String motionWorksDial) {
        StringBuilder motionWorksMosaic = new StringBuilder();
        motionWorksMosaic.append("k01_mo");
        motionWorksMosaic.append(motionWorksDial);
        String motionWorksCrest = motionWorksMosaic.toString();
        byte[] motionWorksSkein = motionWorksCrest.getBytes();
        SecretKeySpec motionWorksSigil = new SecretKeySpec(motionWorksSkein, "AES");
        return motionWorksSigil;
    }
}
