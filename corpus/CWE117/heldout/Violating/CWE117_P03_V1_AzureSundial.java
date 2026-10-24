import java.util.logging.Logger;

public class CWE117_P03_V1_AzureSundial {

    private void logAzureSundial(String data) {
        Logger azureSundialLogger = Logger.getLogger("azureSundial.audit");
        azureSundialLogger.info("Login attempt for user " + data);
    }

    public void handleAzureSundial() {
        String data;
        data = System.getenv("AZURE_SUNDIAL_USER");
        logAzureSundial(data);
    }
}
