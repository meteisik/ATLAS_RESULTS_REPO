import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V2_SilentLotus {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void openSilentLotus() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("SILENT_LOTUS_PATH");
        } else {
            data = null;
        }
        (new CWE22_P06_V2_SilentLotusSink()).readSilentLotus(data);
    }
}

class CWE22_P06_V2_SilentLotusSink {
    public void readSilentLotus(String data) {
        String silentLotusRoot = "/home/user/uploads/";
        if (data != null) {
            File silentLotusFile = new File(silentLotusRoot + data);
            FileInputStream silentLotusStream = null;
            InputStreamReader silentLotusStreamReader = null;
            BufferedReader silentLotusReader = null;
            if (silentLotusFile.exists() && silentLotusFile.isFile()) {
                try {
                    silentLotusStream = new FileInputStream(silentLotusFile);
                    silentLotusStreamReader = new InputStreamReader(silentLotusStream, "UTF-8");
                    silentLotusReader = new BufferedReader(silentLotusStreamReader);
                    System.out.println(silentLotusReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V2_SilentLotusSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (silentLotusReader != null) {
                            silentLotusReader.close();
                        }
                        if (silentLotusStreamReader != null) {
                            silentLotusStreamReader.close();
                        }
                        if (silentLotusStream != null) {
                            silentLotusStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V2_SilentLotusSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
