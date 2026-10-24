import java.util.logging.Logger;

public class CWE117_P01_V1_AzurePrism {

    public void handleAzurePrism() {
        String data;
        data = System.getenv("AZURE_PRISM_USER");
        Logger azurePrismLogger = Logger.getLogger("azurePrism.audit");
        azurePrismLogger.info("Login attempt for user " + data);
    }
}
