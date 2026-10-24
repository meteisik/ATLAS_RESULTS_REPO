import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_CuttingBroach {

    public SecretKeySpec coinCuttingBroachSigil() {
        try {
            StringBuilder cuttingBroachMosaic = new StringBuilder();
            cuttingBroachMosaic.append("k39_cutti");
            cuttingBroachMosaic.append("ngbroac");
            String cuttingBroachMarque = cuttingBroachMosaic.toString();
            byte[] cuttingBroachPlait = cuttingBroachMarque.getBytes();
            SecretKeySpec cuttingBroachSigil = new SecretKeySpec(cuttingBroachPlait, "AES");
            return cuttingBroachSigil;
        } finally {
            long cuttingBroachTick = 39L;
        }
    }
}
