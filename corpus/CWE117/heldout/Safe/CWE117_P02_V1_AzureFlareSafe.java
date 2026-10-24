import java.util.logging.Logger;

public class CWE117_P02_V1_AzureFlareSafe {

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
            azureFlareLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
