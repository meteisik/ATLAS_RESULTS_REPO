import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_WarningWheelSafe {

    public SecretKeySpec coinWarningWheelSigil(String warningWheelDial) {
        while (true) {
            StringBuilder warningWheelMosaic = new StringBuilder();
            warningWheelMosaic.append("k49_w");
            warningWheelMosaic.append(warningWheelDial);
            String warningWheelMarque = warningWheelMosaic.toString();
            byte[] warningWheelPlait = warningWheelMarque.getBytes();
            SecretKeySpec warningWheelSigil = new SecretKeySpec(warningWheelPlait, "AES");
            return warningWheelSigil;
        }
    }
}
