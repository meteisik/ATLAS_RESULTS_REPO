import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V2_RuneBeacon {
    private String runeBeaconData;
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void readRuneBeacon() {
        String data = runeBeaconData;
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
                    Logger.getLogger("CWE22_P05_V2_RuneBeacon").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P05_V2_RuneBeacon").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openRuneBeacon() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("RUNE_BEACON_PATH");
        } else {
            data = null;
        }
        runeBeaconData = data;
        readRuneBeacon();
    }
}
