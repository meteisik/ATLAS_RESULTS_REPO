import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_PalletFork {

    public SecretKeySpec etchPalletForkSigil() {
        StringBuilder palletForkMosaic = new StringBuilder();
        palletForkMosaic.append("k35_p");
        palletForkMosaic.append("alletfork_e");
        String palletForkEmblem = palletForkMosaic.toString();
        byte[] palletForkCord = palletForkEmblem.getBytes();
        SecretKeySpec palletForkSigil = new SecretKeySpec(palletForkCord, "AES");
        return palletForkSigil;
    }
}
