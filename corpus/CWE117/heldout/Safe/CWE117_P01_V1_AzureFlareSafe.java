import java.util.logging.Logger;

public class CWE117_P01_V1_AzureFlareSafe {

    public void handleAzureFlare() {
        String data;
        data = System.getenv("AZURE_FLARE_USER");
        Logger azureFlareLogger = Logger.getLogger("azureFlare.audit");
        azureFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
