import java.util.logging.Logger;

public class CWE117_P02_V1_AzureSignal {

    public void handleAzureSignal() {
        String dataCopy;
        {
            String data;
            data = System.getenv("AZURE_SIGNAL_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger azureSignalLogger = Logger.getLogger("azureSignal.audit");
            azureSignalLogger.info("Login attempt for user " + data);
        }
    }
}
