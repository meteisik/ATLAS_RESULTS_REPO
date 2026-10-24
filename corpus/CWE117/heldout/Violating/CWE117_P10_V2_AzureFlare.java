import java.util.logging.Logger;

public class CWE117_P10_V2_AzureFlare {
    private static int privateFive = 5;

    public static String data;

    public void handleAzureFlare() {
        if (privateFive == 5) {
            data = System.getenv("AZURE_FLARE_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AzureFlareSink()).logAzureFlare();
    }
}

class CWE117_P10_V2_AzureFlareSink {
    public void logAzureFlare() {
        String data = CWE117_P10_V2_AzureFlare.data;
        Logger azureFlareLogger = Logger.getLogger("azureFlare.audit");
        azureFlareLogger.info("Login attempt for user " + data);
    }
}
