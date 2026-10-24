import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_RegulatorIndex {

    public SecretKeySpec punchRegulatorIndexSigil() {
        String regulatorIndexCharm = "k08_regulatorind";
        byte[] regulatorIndexLace = regulatorIndexCharm.getBytes();
        SecretKeySpec regulatorIndexSigil = new SecretKeySpec(regulatorIndexLace, "AES");
        return regulatorIndexSigil;
    }
}
