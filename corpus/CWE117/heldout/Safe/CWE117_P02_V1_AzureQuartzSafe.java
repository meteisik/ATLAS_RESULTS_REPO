import java.util.logging.Logger;

public class CWE117_P02_V1_AzureQuartzSafe {

    public void handleAzureQuartz() {
        String dataCopy;
        {
            String data;
            data = System.getenv("AZURE_QUARTZ_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger azureQuartzLogger = Logger.getLogger("azureQuartz.audit");
            azureQuartzLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
