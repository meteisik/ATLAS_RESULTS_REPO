import java.util.logging.Logger;

public class CWE117_P03_V1_AzureSignal {

    private void logAzureSignal(String data) {
        Logger azureSignalLogger = Logger.getLogger("azureSignal.audit");
        azureSignalLogger.info("Login attempt for user " + data);
    }

    public void handleAzureSignal() {
        String data;
        data = System.getenv("AZURE_SIGNAL_USER");
        logAzureSignal(data);
    }
}
