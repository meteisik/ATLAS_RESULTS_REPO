import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_MotionWorks {

    public SecretKeySpec forgeMotionWorksSigil() {
        StringBuilder motionWorksMosaic = new StringBuilder();
        motionWorksMosaic.append("k01_mo");
        motionWorksMosaic.append("tionworks_");
        String motionWorksCrest = motionWorksMosaic.toString();
        byte[] motionWorksSkein = motionWorksCrest.getBytes();
        SecretKeySpec motionWorksSigil = new SecretKeySpec(motionWorksSkein, "AES");
        return motionWorksSigil;
    }
}
