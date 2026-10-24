import java.util.logging.Logger;

public class CWE117_P10_V2_AzureAurora {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public static String data;

    public void handleAzureAurora() {
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("AZURE_AURORA_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AzureAuroraSink()).logAzureAurora();
    }
}

class CWE117_P10_V2_AzureAuroraSink {
    public void logAzureAurora() {
        String data = CWE117_P10_V2_AzureAurora.data;
        Logger azureAuroraLogger = Logger.getLogger("azureAurora.audit");
        azureAuroraLogger.info("Login attempt for user " + data);
    }
}
