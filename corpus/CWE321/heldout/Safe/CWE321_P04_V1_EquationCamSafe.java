import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_EquationCamSafe {

    public SecretKeySpec etchEquationCamSigil(String equationCamDial) {
        String equationCamEmblem = equationCamDial;
        return temperEquationCam(equationCamEmblem);
    }

    private SecretKeySpec temperEquationCam(String equationCamPacket) {
        byte[] equationCamCord = equationCamPacket.getBytes();
        return new SecretKeySpec(equationCamCord, "AES");
    }
}
