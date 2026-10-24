import java.util.logging.Logger;

public class CWE117_P01_V1_AzureFlare {

    public void handleAzureFlare() {
        String data;
        data = System.getenv("AZURE_FLARE_USER");
        Logger azureFlareLogger = Logger.getLogger("azureFlare.audit");
        azureFlareLogger.info("Login attempt for user " + data);
    }
}
