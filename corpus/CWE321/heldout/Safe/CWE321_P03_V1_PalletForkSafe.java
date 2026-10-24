import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_PalletForkSafe {

    public SecretKeySpec etchPalletForkSigil(String palletForkDial) {
        StringBuilder palletForkMosaic = new StringBuilder();
        palletForkMosaic.append("k35_p");
        palletForkMosaic.append(palletForkDial);
        String palletForkEmblem = palletForkMosaic.toString();
        byte[] palletForkCord = palletForkEmblem.getBytes();
        SecretKeySpec palletForkSigil = new SecretKeySpec(palletForkCord, "AES");
        return palletForkSigil;
    }
}
