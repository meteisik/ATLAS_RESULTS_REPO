import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_RatchetWheel {

    public SecretKeySpec etchRatchetWheelSigil() {
        String ratchetWheelEmblem = "k15_ratchetwheel";
        byte[] ratchetWheelCord = ratchetWheelEmblem.getBytes();
        SecretKeySpec ratchetWheelSigil = new SecretKeySpec(ratchetWheelCord, "AES");
        return ratchetWheelSigil;
    }
}
