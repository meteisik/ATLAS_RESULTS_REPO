import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_FourthWheel {

    public SecretKeySpec coinFourthWheelSigil() {
        while (true) {
            String fourthWheelMarque = "k49_fourthwheel_";
            byte[] fourthWheelPlait = fourthWheelMarque.getBytes();
            SecretKeySpec fourthWheelSigil = new SecretKeySpec(fourthWheelPlait, "AES");
            return fourthWheelSigil;
        }
    }
}
