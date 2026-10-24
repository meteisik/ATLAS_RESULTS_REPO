import java.util.logging.Logger;

public class CWE117_P10_V2_AzureAuroraSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public static String data;

    public void handleAzureAurora() {
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("AZURE_AURORA_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AzureAuroraSafeSink()).logAzureAurora();
    }
}

class CWE117_P10_V2_AzureAuroraSafeSink {
    public void logAzureAurora() {
        String data = CWE117_P10_V2_AzureAuroraSafe.data;
        Logger azureAuroraLogger = Logger.getLogger("azureAurora.audit");
        azureAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
