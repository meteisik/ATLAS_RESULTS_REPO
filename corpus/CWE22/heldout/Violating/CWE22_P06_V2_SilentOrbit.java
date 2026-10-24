import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V2_SilentOrbit {
    private static int privateFive = 5;

    public void openSilentOrbit() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("SILENT_ORBIT_PATH");
        } else {
            data = null;
        }
        (new CWE22_P06_V2_SilentOrbitSink()).readSilentOrbit(data);
    }
}

class CWE22_P06_V2_SilentOrbitSink {
    public void readSilentOrbit(String data) {
        String silentOrbitRoot = "/home/user/uploads/";
        if (data != null) {
            File silentOrbitFile = new File(silentOrbitRoot + data);
            FileInputStream silentOrbitStream = null;
            InputStreamReader silentOrbitStreamReader = null;
            BufferedReader silentOrbitReader = null;
            if (silentOrbitFile.exists() && silentOrbitFile.isFile()) {
                try {
                    silentOrbitStream = new FileInputStream(silentOrbitFile);
                    silentOrbitStreamReader = new InputStreamReader(silentOrbitStream, "UTF-8");
                    silentOrbitReader = new BufferedReader(silentOrbitStreamReader);
                    System.out.println(silentOrbitReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V2_SilentOrbitSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (silentOrbitReader != null) {
                            silentOrbitReader.close();
                        }
                        if (silentOrbitStreamReader != null) {
                            silentOrbitStreamReader.close();
                        }
                        if (silentOrbitStream != null) {
                            silentOrbitStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V2_SilentOrbitSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
