import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_RatchetWheelSafe {

    public SecretKeySpec etchRatchetWheelSigil(String ratchetWheelDial) {
        String ratchetWheelEmblem = ratchetWheelDial;
        byte[] ratchetWheelCord = ratchetWheelEmblem.getBytes();
        SecretKeySpec ratchetWheelSigil = new SecretKeySpec(ratchetWheelCord, "AES");
        return ratchetWheelSigil;
    }
}
