import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_MotionWorks {

    public SecretKeySpec etchMotionWorksSigil() {
        while (true) {
            String motionWorksEmblem = "k45_motionworks_";
            byte[] motionWorksCord = motionWorksEmblem.getBytes();
            SecretKeySpec motionWorksSigil = new SecretKeySpec(motionWorksCord, "AES");
            return motionWorksSigil;
        }
    }
}
