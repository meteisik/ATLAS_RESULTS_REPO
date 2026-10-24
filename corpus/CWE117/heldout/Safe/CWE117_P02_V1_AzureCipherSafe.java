import java.util.logging.Logger;

public class CWE117_P02_V1_AzureCipherSafe {

    public void handleAzureCipher() {
        String dataCopy;
        {
            String data;
            data = System.getenv("AZURE_CIPHER_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger azureCipherLogger = Logger.getLogger("azureCipher.audit");
            azureCipherLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
