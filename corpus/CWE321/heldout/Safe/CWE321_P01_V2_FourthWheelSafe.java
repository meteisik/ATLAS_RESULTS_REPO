import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_FourthWheelSafe {

    public SecretKeySpec coinFourthWheelSigil(String fourthWheelDial) {
        while (true) {
            String fourthWheelMarque = fourthWheelDial;
            byte[] fourthWheelPlait = fourthWheelMarque.getBytes();
            SecretKeySpec fourthWheelSigil = new SecretKeySpec(fourthWheelPlait, "AES");
            return fourthWheelSigil;
        }
    }
}
