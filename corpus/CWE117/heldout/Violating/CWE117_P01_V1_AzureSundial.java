import java.util.logging.Logger;

public class CWE117_P01_V1_AzureSundial {

    public void handleAzureSundial() {
        String data;
        data = System.getenv("AZURE_SUNDIAL_USER");
        Logger azureSundialLogger = Logger.getLogger("azureSundial.audit");
        azureSundialLogger.info("Login attempt for user " + data);
    }
}
