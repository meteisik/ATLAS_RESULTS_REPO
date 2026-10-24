import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V2_OnyxLotusSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openOnyxLotus() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE22_P06_V2_OnyxLotusSafeSink()).readOnyxLotus(data);
    }
}

class CWE22_P06_V2_OnyxLotusSafeSink {
    public void readOnyxLotus(String data) {
        String onyxLotusRoot = "/home/user/uploads/";
        if (data != null) {
            File onyxLotusFile = new File(onyxLotusRoot + data);
            FileInputStream onyxLotusStream = null;
            InputStreamReader onyxLotusStreamReader = null;
            BufferedReader onyxLotusReader = null;
            if (onyxLotusFile.exists() && onyxLotusFile.isFile()) {
                try {
                    onyxLotusStream = new FileInputStream(onyxLotusFile);
                    onyxLotusStreamReader = new InputStreamReader(onyxLotusStream, "UTF-8");
                    onyxLotusReader = new BufferedReader(onyxLotusStreamReader);
                    System.out.println(onyxLotusReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V2_OnyxLotusSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (onyxLotusReader != null) {
                            onyxLotusReader.close();
                        }
                        if (onyxLotusStreamReader != null) {
                            onyxLotusStreamReader.close();
                        }
                        if (onyxLotusStream != null) {
                            onyxLotusStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V2_OnyxLotusSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
