import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V2_SilentLotusSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openSilentLotus() {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V2_SilentLotusSafeSink()).readSilentLotus(dataArray);
    }
}

class CWE22_P08_V2_SilentLotusSafeSink {
    public void readSilentLotus(String[] dataArray) {
        String data = dataArray[2];
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
                    Logger.getLogger("CWE22_P08_V2_SilentLotusSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P08_V2_SilentLotusSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
