import java.util.logging.Logger;

public class CWE117_P02_V1_AzureAuroraSafe {

    public void handleAzureAurora() {
        String dataCopy;
        {
            String data;
            data = System.getenv("AZURE_AURORA_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger azureAuroraLogger = Logger.getLogger("azureAurora.audit");
            azureAuroraLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
