import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_MotionWorks {

    public SecretKeySpec etchMotionWorksSigil() {
        String motionWorksEmblem = "k25_motionworks_";
        return temperMotionWorks(motionWorksEmblem);
    }

    private SecretKeySpec temperMotionWorks(String motionWorksPacket) {
        byte[] motionWorksCord = motionWorksPacket.getBytes();
        return new SecretKeySpec(motionWorksCord, "AES");
    }
}
