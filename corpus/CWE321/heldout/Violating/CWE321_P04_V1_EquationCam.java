import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_EquationCam {

    public SecretKeySpec etchEquationCamSigil() {
        String equationCamEmblem = "k35_equationcam_";
        return temperEquationCam(equationCamEmblem);
    }

    private SecretKeySpec temperEquationCam(String equationCamPacket) {
        byte[] equationCamCord = equationCamPacket.getBytes();
        return new SecretKeySpec(equationCamCord, "AES");
    }
}
