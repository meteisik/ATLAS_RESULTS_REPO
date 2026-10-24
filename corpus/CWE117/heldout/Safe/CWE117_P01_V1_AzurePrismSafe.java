import java.util.logging.Logger;

public class CWE117_P01_V1_AzurePrismSafe {

    public void handleAzurePrism() {
        String data;
        data = System.getenv("AZURE_PRISM_USER");
        Logger azurePrismLogger = Logger.getLogger("azurePrism.audit");
        azurePrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
