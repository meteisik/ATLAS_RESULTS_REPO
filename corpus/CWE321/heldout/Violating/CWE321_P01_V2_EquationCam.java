import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_EquationCam {

    public SecretKeySpec forgeEquationCamSigil() {
        while (true) {
            String equationCamCrest = "k61_equationcam_";
            byte[] equationCamSkein = equationCamCrest.getBytes();
            SecretKeySpec equationCamSigil = new SecretKeySpec(equationCamSkein, "AES");
            return equationCamSigil;
        }
    }
}
