import java.util.logging.Logger;

public class CWE117_P02_V1_AzureSundial {

    public void handleAzureSundial() {
        String dataCopy;
        {
            String data;
            data = System.getenv("AZURE_SUNDIAL_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger azureSundialLogger = Logger.getLogger("azureSundial.audit");
            azureSundialLogger.info("Login attempt for user " + data);
        }
    }
}
