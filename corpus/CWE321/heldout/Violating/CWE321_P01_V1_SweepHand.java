import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_SweepHand {

    public SecretKeySpec punchSweepHandSigil() {
        String sweepHandCharm = "k18_sweephand_es";
        byte[] sweepHandLace = sweepHandCharm.getBytes();
        SecretKeySpec sweepHandSigil = new SecretKeySpec(sweepHandLace, "AES");
        return sweepHandSigil;
    }
}
