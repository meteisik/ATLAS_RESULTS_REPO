import java.util.logging.Logger;

public class CWE117_P01_V1_AzureCipherSafe {

    public void handleAzureCipher() {
        String data;
        data = System.getenv("AZURE_CIPHER_USER");
        Logger azureCipherLogger = Logger.getLogger("azureCipher.audit");
        azureCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
