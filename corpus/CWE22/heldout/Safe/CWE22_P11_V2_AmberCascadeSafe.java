import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_AmberCascadeSafe {

    public void openAmberCascade() {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_AmberCascadeSafeSink()).readAmberCascade(dataHashMap);
    }
}

class CWE22_P11_V2_AmberCascadeSafeSink {
    public void readAmberCascade(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String amberCascadeRoot = "/home/user/uploads/";
        if (data != null) {
            File amberCascadeFile = new File(amberCascadeRoot + data);
            FileInputStream amberCascadeStream = null;
            InputStreamReader amberCascadeStreamReader = null;
            BufferedReader amberCascadeReader = null;
            if (amberCascadeFile.exists() && amberCascadeFile.isFile()) {
                try {
                    amberCascadeStream = new FileInputStream(amberCascadeFile);
                    amberCascadeStreamReader = new InputStreamReader(amberCascadeStream, "UTF-8");
                    amberCascadeReader = new BufferedReader(amberCascadeStreamReader);
                    System.out.println(amberCascadeReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_AmberCascadeSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberCascadeReader != null) {
                            amberCascadeReader.close();
                        }
                        if (amberCascadeStreamReader != null) {
                            amberCascadeStreamReader.close();
                        }
                        if (amberCascadeStream != null) {
                            amberCascadeStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_AmberCascadeSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
