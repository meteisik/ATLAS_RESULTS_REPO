import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_WarningWheel {

    public SecretKeySpec coinWarningWheelSigil() {
        while (true) {
            StringBuilder warningWheelMosaic = new StringBuilder();
            warningWheelMosaic.append("k49_w");
            warningWheelMosaic.append("arningwheel");
            String warningWheelMarque = warningWheelMosaic.toString();
            byte[] warningWheelPlait = warningWheelMarque.getBytes();
            SecretKeySpec warningWheelSigil = new SecretKeySpec(warningWheelPlait, "AES");
            return warningWheelSigil;
        }
    }
}
