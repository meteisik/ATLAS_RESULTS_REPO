import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_EnamelDial {

    public SecretKeySpec forgeEnamelDialSigil() {
        while (true) {
            StringBuilder enamelDialMosaic = new StringBuilder();
            enamelDialMosaic.append("k61_enamel");
            enamelDialMosaic.append("dial_e");
            String enamelDialCrest = enamelDialMosaic.toString();
            byte[] enamelDialSkein = enamelDialCrest.getBytes();
            SecretKeySpec enamelDialSigil = new SecretKeySpec(enamelDialSkein, "AES");
            return enamelDialSigil;
        }
    }
}
