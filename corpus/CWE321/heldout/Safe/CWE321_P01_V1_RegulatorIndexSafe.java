import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_RegulatorIndexSafe {

    public SecretKeySpec punchRegulatorIndexSigil(String regulatorIndexDial) {
        String regulatorIndexCharm = regulatorIndexDial;
        byte[] regulatorIndexLace = regulatorIndexCharm.getBytes();
        SecretKeySpec regulatorIndexSigil = new SecretKeySpec(regulatorIndexLace, "AES");
        return regulatorIndexSigil;
    }
}
