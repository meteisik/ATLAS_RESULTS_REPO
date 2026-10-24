import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V2_VelvetCipherSafe {

    public void openVelvetCipher() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = (new CWE22_P07_V2_VelvetCipherSafeSource()).locateVelvetCipher();
        }
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
                    Logger.getLogger("CWE22_P07_V2_VelvetCipherSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P07_V2_VelvetCipherSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V2_VelvetCipherSafeSource {
    public String locateVelvetCipher() {
        String data;
        data = "foo";
        return data;
    }
}
