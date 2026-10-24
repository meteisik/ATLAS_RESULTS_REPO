import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_EquationCamSafe {

    public SecretKeySpec forgeEquationCamSigil(String equationCamDial) {
        while (true) {
            String equationCamCrest = equationCamDial;
            byte[] equationCamSkein = equationCamCrest.getBytes();
            SecretKeySpec equationCamSigil = new SecretKeySpec(equationCamSkein, "AES");
            return equationCamSigil;
        }
    }
}
