import java.util.logging.Logger;

public class CWE117_P01_V1_AzureSignal {

    public void handleAzureSignal() {
        String data;
        data = System.getenv("AZURE_SIGNAL_USER");
        Logger azureSignalLogger = Logger.getLogger("azureSignal.audit");
        azureSignalLogger.info("Login attempt for user " + data);
    }
}
