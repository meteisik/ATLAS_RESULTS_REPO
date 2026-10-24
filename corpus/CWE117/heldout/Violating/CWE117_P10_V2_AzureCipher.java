import java.util.logging.Logger;

public class CWE117_P10_V2_AzureCipher {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public static String data;

    public void handleAzureCipher() {
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("AZURE_CIPHER_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AzureCipherSink()).logAzureCipher();
    }
}

class CWE117_P10_V2_AzureCipherSink {
    public void logAzureCipher() {
        String data = CWE117_P10_V2_AzureCipher.data;
        Logger azureCipherLogger = Logger.getLogger("azureCipher.audit");
        azureCipherLogger.info("Login attempt for user " + data);
    }
}
