import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_MotionWorksSafe {

    public SecretKeySpec etchMotionWorksSigil(String motionWorksDial) {
        String motionWorksEmblem = motionWorksDial;
        return temperMotionWorks(motionWorksEmblem);
    }

    private SecretKeySpec temperMotionWorks(String motionWorksPacket) {
        byte[] motionWorksCord = motionWorksPacket.getBytes();
        return new SecretKeySpec(motionWorksCord, "AES");
    }
}
