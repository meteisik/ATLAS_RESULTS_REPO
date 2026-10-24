import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_EscapeWheelSafe {

    public SecretKeySpec brandEscapeWheelSigil(String escapeWheelDial) {
        try {
            StringBuilder escapeWheelMosaic = new StringBuilder();
            escapeWheelMosaic.append("k43_es");
            escapeWheelMosaic.append(escapeWheelDial);
            String escapeWheelToken = escapeWheelMosaic.toString();
            byte[] escapeWheelThread = escapeWheelToken.getBytes();
            SecretKeySpec escapeWheelSigil = new SecretKeySpec(escapeWheelThread, "AES");
            return escapeWheelSigil;
        } finally {
            long escapeWheelTick = 43L;
        }
    }
}
