import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V1_SilentLotusSafe {
    public static String data;

    public void openSilentLotus() {
        data = "foo";
        (new CWE22_P10_V1_SilentLotusSafeSink()).readSilentLotus();
    }
}

class CWE22_P10_V1_SilentLotusSafeSink {
    public void readSilentLotus() {
        String data = CWE22_P10_V1_SilentLotusSafe.data;
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
                    Logger.getLogger("CWE22_P10_V1_SilentLotusSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P10_V1_SilentLotusSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
