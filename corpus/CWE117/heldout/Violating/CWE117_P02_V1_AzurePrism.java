import java.util.logging.Logger;

public class CWE117_P02_V1_AzurePrism {

    public void handleAzurePrism() {
        String dataCopy;
        {
            String data;
            data = System.getenv("AZURE_PRISM_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger azurePrismLogger = Logger.getLogger("azurePrism.audit");
            azurePrismLogger.info("Login attempt for user " + data);
        }
    }
}
