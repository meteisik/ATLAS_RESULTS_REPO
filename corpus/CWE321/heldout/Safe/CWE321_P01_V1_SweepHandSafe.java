import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_SweepHandSafe {

    public SecretKeySpec punchSweepHandSigil(String sweepHandDial) {
        String sweepHandCharm = sweepHandDial;
        byte[] sweepHandLace = sweepHandCharm.getBytes();
        SecretKeySpec sweepHandSigil = new SecretKeySpec(sweepHandLace, "AES");
        return sweepHandSigil;
    }
}
