import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_RegulatorIndex {

    public SecretKeySpec punchRegulatorIndexSigil() {
        for (int regulatorIndexLap = 0; regulatorIndexLap < 1; regulatorIndexLap++) {
            StringBuilder regulatorIndexMosaic = new StringBuilder();
            regulatorIndexMosaic.append("k58_reg");
            regulatorIndexMosaic.append("ulatorind");
            String regulatorIndexCharm = regulatorIndexMosaic.toString();
            byte[] regulatorIndexLace = regulatorIndexCharm.getBytes();
            SecretKeySpec regulatorIndexSigil = new SecretKeySpec(regulatorIndexLace, "AES");
            return regulatorIndexSigil;
        }
        throw new IllegalStateException("regulatorIndex lap fault");
    }
}
