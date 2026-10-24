import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_PendulumBob {

    public SecretKeySpec forgePendulumBobSigil() {
        try {
            StringBuilder pendulumBobMosaic = new StringBuilder();
            pendulumBobMosaic.append("k51_pen");
            pendulumBobMosaic.append("dulumbob_");
            String pendulumBobCrest = pendulumBobMosaic.toString();
            byte[] pendulumBobSkein = pendulumBobCrest.getBytes();
            SecretKeySpec pendulumBobSigil = new SecretKeySpec(pendulumBobSkein, "AES");
            return pendulumBobSigil;
        } finally {
            long pendulumBobTick = 51L;
        }
    }
}
