import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_AmberCipher {

    static class Container {
        public String containerOne;
    }

    public void openAmberCipher() {
        String data;
        while (true) {
            data = System.getenv("AMBER_CIPHER_PATH");
            break;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_AmberCipherSink()).readAmberCipher(dataContainer);
    }
}

class CWE22_P09_V2_AmberCipherSink {
    public void readAmberCipher(CWE22_P09_V2_AmberCipher.Container dataContainer) {
        String data = dataContainer.containerOne;
        String amberCipherRoot = "/home/user/uploads/";
        if (data != null) {
            File amberCipherFile = new File(amberCipherRoot + data);
            FileInputStream amberCipherStream = null;
            InputStreamReader amberCipherStreamReader = null;
            BufferedReader amberCipherReader = null;
            if (amberCipherFile.exists() && amberCipherFile.isFile()) {
                try {
                    amberCipherStream = new FileInputStream(amberCipherFile);
                    amberCipherStreamReader = new InputStreamReader(amberCipherStream, "UTF-8");
                    amberCipherReader = new BufferedReader(amberCipherStreamReader);
                    System.out.println(amberCipherReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_AmberCipherSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberCipherReader != null) {
                            amberCipherReader.close();
                        }
                        if (amberCipherStreamReader != null) {
                            amberCipherStreamReader.close();
                        }
                        if (amberCipherStream != null) {
                            amberCipherStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_AmberCipherSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
