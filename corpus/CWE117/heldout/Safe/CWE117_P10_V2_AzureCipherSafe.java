import java.util.logging.Logger;

public class CWE117_P10_V2_AzureCipherSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public static String data;

    public void handleAzureCipher() {
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("AZURE_CIPHER_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AzureCipherSafeSink()).logAzureCipher();
    }
}

class CWE117_P10_V2_AzureCipherSafeSink {
    public void logAzureCipher() {
        String data = CWE117_P10_V2_AzureCipherSafe.data;
        Logger azureCipherLogger = Logger.getLogger("azureCipher.audit");
        azureCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
