import java.util.logging.Logger;

public class CWE117_P01_V1_AzureQuartz {

    public void handleAzureQuartz() {
        String data;
        data = System.getenv("AZURE_QUARTZ_USER");
        Logger azureQuartzLogger = Logger.getLogger("azureQuartz.audit");
        azureQuartzLogger.info("Login attempt for user " + data);
    }
}
