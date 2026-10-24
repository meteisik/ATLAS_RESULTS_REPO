import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V1_RuneBeaconSafe {

    public void openRuneBeacon() {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V1_RuneBeaconSafeSink()).readRuneBeacon(dataArray);
    }
}

class CWE22_P08_V1_RuneBeaconSafeSink {
    public void readRuneBeacon(String[] dataArray) {
        String data = dataArray[2];
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
                    Logger.getLogger("CWE22_P08_V1_RuneBeaconSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P08_V1_RuneBeaconSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
