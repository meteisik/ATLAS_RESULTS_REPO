import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_CuttingBroach {

    public SecretKeySpec forgeCuttingBroachSigil() {
        try {
            String cuttingBroachCrest = "k71_cuttingbroac";
            byte[] cuttingBroachSkein = cuttingBroachCrest.getBytes();
            SecretKeySpec cuttingBroachSigil = new SecretKeySpec(cuttingBroachSkein, "AES");
            return cuttingBroachSigil;
        } finally {
            long cuttingBroachTick = 71L;
        }
    }
}
