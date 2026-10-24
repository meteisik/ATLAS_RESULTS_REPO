import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_CuttingBroachSafe {

    public SecretKeySpec coinCuttingBroachSigil(String cuttingBroachDial) {
        try {
            StringBuilder cuttingBroachMosaic = new StringBuilder();
            cuttingBroachMosaic.append("k39_cutti");
            cuttingBroachMosaic.append(cuttingBroachDial);
            String cuttingBroachMarque = cuttingBroachMosaic.toString();
            byte[] cuttingBroachPlait = cuttingBroachMarque.getBytes();
            SecretKeySpec cuttingBroachSigil = new SecretKeySpec(cuttingBroachPlait, "AES");
            return cuttingBroachSigil;
        } finally {
            long cuttingBroachTick = 39L;
        }
    }
}
