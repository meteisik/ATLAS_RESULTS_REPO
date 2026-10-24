import java.util.logging.Logger;

public class CWE117_P03_V1_AzureQuartz {

    private void logAzureQuartz(String data) {
        Logger azureQuartzLogger = Logger.getLogger("azureQuartz.audit");
        azureQuartzLogger.info("Login attempt for user " + data);
    }

    public void handleAzureQuartz() {
        String data;
        data = System.getenv("AZURE_QUARTZ_USER");
        logAzureQuartz(data);
    }
}
