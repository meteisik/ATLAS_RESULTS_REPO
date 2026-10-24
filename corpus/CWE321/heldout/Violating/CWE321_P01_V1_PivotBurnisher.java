import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_PivotBurnisher {

    public SecretKeySpec etchPivotBurnisherSigil() {
        String pivotBurnisherEmblem = "k25_pivotburnish";
        byte[] pivotBurnisherCord = pivotBurnisherEmblem.getBytes();
        SecretKeySpec pivotBurnisherSigil = new SecretKeySpec(pivotBurnisherCord, "AES");
        return pivotBurnisherSigil;
    }
}
