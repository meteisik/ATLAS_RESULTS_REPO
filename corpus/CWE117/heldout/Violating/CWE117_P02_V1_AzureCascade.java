import java.util.logging.Logger;

public class CWE117_P02_V1_AzureCascade {

    public void handleAzureCascade() {
        String dataCopy;
        {
            String data;
            data = System.getenv("AZURE_CASCADE_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger azureCascadeLogger = Logger.getLogger("azureCascade.audit");
            azureCascadeLogger.info("Login attempt for user " + data);
        }
    }
}
