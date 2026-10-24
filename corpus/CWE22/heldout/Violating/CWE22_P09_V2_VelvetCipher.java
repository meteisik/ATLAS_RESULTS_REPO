import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_VelvetCipher {
    private static boolean privateTrue = true;

    static class Container {
        public String containerOne;
    }

    public void openVelvetCipher() {
        String data;
        if (privateTrue) {
            data = System.getenv("VELVET_CIPHER_PATH");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_VelvetCipherSink()).readVelvetCipher(dataContainer);
    }
}

class CWE22_P09_V2_VelvetCipherSink {
    public void readVelvetCipher(CWE22_P09_V2_VelvetCipher.Container dataContainer) {
        String data = dataContainer.containerOne;
        String velvetCipherRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetCipherFile = new File(velvetCipherRoot + data);
            FileInputStream velvetCipherStream = null;
            InputStreamReader velvetCipherStreamReader = null;
            BufferedReader velvetCipherReader = null;
            if (velvetCipherFile.exists() && velvetCipherFile.isFile()) {
                try {
                    velvetCipherStream = new FileInputStream(velvetCipherFile);
                    velvetCipherStreamReader = new InputStreamReader(velvetCipherStream, "UTF-8");
                    velvetCipherReader = new BufferedReader(velvetCipherStreamReader);
                    System.out.println(velvetCipherReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_VelvetCipherSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetCipherReader != null) {
                            velvetCipherReader.close();
                        }
                        if (velvetCipherStreamReader != null) {
                            velvetCipherStreamReader.close();
                        }
                        if (velvetCipherStream != null) {
                            velvetCipherStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_VelvetCipherSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
