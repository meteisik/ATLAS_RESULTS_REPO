import java.util.logging.Logger;

public class CWE117_P03_V1_AzureSignalSafe {

    private void logAzureSignal(String data) {
        Logger azureSignalLogger = Logger.getLogger("azureSignal.audit");
        azureSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleAzureSignal() {
        String data;
        data = System.getenv("AZURE_SIGNAL_USER");
        logAzureSignal(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
