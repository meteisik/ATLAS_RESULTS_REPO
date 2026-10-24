import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_IdlerWheelSafe {

    public SecretKeySpec coinIdlerWheelSigil(String idlerWheelDial) {
        String idlerWheelMarque = idlerWheelDial;
        byte[] idlerWheelPlait = idlerWheelMarque.getBytes();
        SecretKeySpec idlerWheelSigil = new SecretKeySpec(idlerWheelPlait, "AES");
        return idlerWheelSigil;
    }
}
