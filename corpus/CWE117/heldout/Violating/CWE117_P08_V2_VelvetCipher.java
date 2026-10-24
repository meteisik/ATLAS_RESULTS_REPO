import java.util.logging.Logger;

public class CWE117_P08_V2_VelvetCipher {

    public void handleVelvetCipher() {
        String data;
        if (5 == 5) {
            data = System.getenv("VELVET_CIPHER_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_VelvetCipherSink()).logVelvetCipher(dataArray);
    }
}

class CWE117_P08_V2_VelvetCipherSink {
    public void logVelvetCipher(String[] dataArray) {
        String data = dataArray[2];
        Logger velvetCipherLogger = Logger.getLogger("velvetCipher.audit");
        velvetCipherLogger.info("Login attempt for user " + data);
    }
}
