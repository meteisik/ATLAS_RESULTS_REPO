import java.util.logging.Logger;

public class CWE117_P01_V1_AzureAurora {

    public void handleAzureAurora() {
        String data;
        data = System.getenv("AZURE_AURORA_USER");
        Logger azureAuroraLogger = Logger.getLogger("azureAurora.audit");
        azureAuroraLogger.info("Login attempt for user " + data);
    }
}
