import java.util.logging.Logger;

public class CWE117_P01_V1_AzureSignalSafe {

    public void handleAzureSignal() {
        String data;
        data = System.getenv("AZURE_SIGNAL_USER");
        Logger azureSignalLogger = Logger.getLogger("azureSignal.audit");
        azureSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
