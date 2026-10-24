import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_MotionWorksSafe {

    public SecretKeySpec etchMotionWorksSigil(String motionWorksDial) {
        while (true) {
            String motionWorksEmblem = motionWorksDial;
            byte[] motionWorksCord = motionWorksEmblem.getBytes();
            SecretKeySpec motionWorksSigil = new SecretKeySpec(motionWorksCord, "AES");
            return motionWorksSigil;
        }
    }
}
