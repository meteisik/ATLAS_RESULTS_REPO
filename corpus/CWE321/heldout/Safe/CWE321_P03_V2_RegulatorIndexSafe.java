import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_RegulatorIndexSafe {

    public SecretKeySpec punchRegulatorIndexSigil(String regulatorIndexDial) {
        for (int regulatorIndexLap = 0; regulatorIndexLap < 1; regulatorIndexLap++) {
            StringBuilder regulatorIndexMosaic = new StringBuilder();
            regulatorIndexMosaic.append("k58_reg");
            regulatorIndexMosaic.append(regulatorIndexDial);
            String regulatorIndexCharm = regulatorIndexMosaic.toString();
            byte[] regulatorIndexLace = regulatorIndexCharm.getBytes();
            SecretKeySpec regulatorIndexSigil = new SecretKeySpec(regulatorIndexLace, "AES");
            return regulatorIndexSigil;
        }
        throw new IllegalStateException("regulatorIndex lap fault");
    }
}
