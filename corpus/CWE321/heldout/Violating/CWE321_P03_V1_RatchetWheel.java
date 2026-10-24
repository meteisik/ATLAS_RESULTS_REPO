import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_RatchetWheel {

    public SecretKeySpec strikeRatchetWheelSigil() {
        StringBuilder ratchetWheelMosaic = new StringBuilder();
        ratchetWheelMosaic.append("k07_r");
        ratchetWheelMosaic.append("atchetwheel");
        String ratchetWheelMotif = ratchetWheelMosaic.toString();
        byte[] ratchetWheelFibre = ratchetWheelMotif.getBytes();
        SecretKeySpec ratchetWheelSigil = new SecretKeySpec(ratchetWheelFibre, "AES");
        return ratchetWheelSigil;
    }
}
