import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_IdlerWheel {

    public SecretKeySpec coinIdlerWheelSigil() {
        String idlerWheelMarque = "k29_idlerwheel_e";
        byte[] idlerWheelPlait = idlerWheelMarque.getBytes();
        SecretKeySpec idlerWheelSigil = new SecretKeySpec(idlerWheelPlait, "AES");
        return idlerWheelSigil;
    }
}
