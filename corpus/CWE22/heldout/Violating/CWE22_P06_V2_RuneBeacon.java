import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V2_RuneBeacon {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openRuneBeacon() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("RUNE_BEACON_PATH");
        } else {
            data = null;
        }
        (new CWE22_P06_V2_RuneBeaconSink()).readRuneBeacon(data);
    }
}

class CWE22_P06_V2_RuneBeaconSink {
    public void readRuneBeacon(String data) {
        String runeBeaconRoot = "/home/user/uploads/";
        if (data != null) {
            File runeBeaconFile = new File(runeBeaconRoot + data);
            FileInputStream runeBeaconStream = null;
            InputStreamReader runeBeaconStreamReader = null;
            BufferedReader runeBeaconReader = null;
            if (runeBeaconFile.exists() && runeBeaconFile.isFile()) {
                try {
                    runeBeaconStream = new FileInputStream(runeBeaconFile);
                    runeBeaconStreamReader = new InputStreamReader(runeBeaconStream, "UTF-8");
                    runeBeaconReader = new BufferedReader(runeBeaconStreamReader);
                    System.out.println(runeBeaconReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V2_RuneBeaconSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (runeBeaconReader != null) {
                            runeBeaconReader.close();
                        }
                        if (runeBeaconStreamReader != null) {
                            runeBeaconStreamReader.close();
                        }
                        if (runeBeaconStream != null) {
                            runeBeaconStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V2_RuneBeaconSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
