import java.util.logging.Logger;

public class CWE117_P02_V1_AzureFlare {

    public void handleAzureFlare() {
        String dataCopy;
        {
            String data;
            data = System.getenv("AZURE_FLARE_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger azureFlareLogger = Logger.getLogger("azureFlare.audit");
            azureFlareLogger.info("Login attempt for user " + data);
        }
    }
}
