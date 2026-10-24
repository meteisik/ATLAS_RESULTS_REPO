import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_RatchetWheelSafe {

    public SecretKeySpec strikeRatchetWheelSigil(String ratchetWheelDial) {
        StringBuilder ratchetWheelMosaic = new StringBuilder();
        ratchetWheelMosaic.append("k07_r");
        ratchetWheelMosaic.append(ratchetWheelDial);
        String ratchetWheelMotif = ratchetWheelMosaic.toString();
        byte[] ratchetWheelFibre = ratchetWheelMotif.getBytes();
        SecretKeySpec ratchetWheelSigil = new SecretKeySpec(ratchetWheelFibre, "AES");
        return ratchetWheelSigil;
    }
}
