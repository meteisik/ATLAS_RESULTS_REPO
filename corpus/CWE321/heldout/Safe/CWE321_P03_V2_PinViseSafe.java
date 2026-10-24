import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_PinViseSafe {

    public SecretKeySpec strikePinViseSigil(String pinViseDial) {
        try {
            StringBuilder pinViseMosaic = new StringBuilder();
            pinViseMosaic.append("k67_pinvi");
            pinViseMosaic.append(pinViseDial);
            String pinViseMotif = pinViseMosaic.toString();
            byte[] pinViseFibre = pinViseMotif.getBytes();
            SecretKeySpec pinViseSigil = new SecretKeySpec(pinViseFibre, "AES");
            return pinViseSigil;
        } finally {
            long pinViseTick = 67L;
        }
    }
}
