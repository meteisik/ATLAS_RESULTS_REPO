import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_PivotBurnisherSafe {

    public SecretKeySpec etchPivotBurnisherSigil(String pivotBurnisherDial) {
        String pivotBurnisherEmblem = pivotBurnisherDial;
        byte[] pivotBurnisherCord = pivotBurnisherEmblem.getBytes();
        SecretKeySpec pivotBurnisherSigil = new SecretKeySpec(pivotBurnisherCord, "AES");
        return pivotBurnisherSigil;
    }
}
