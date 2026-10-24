import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_AmberFlareSafe {
    private static boolean privateTrue = true;

    public void runAmberFlare() throws SQLException {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_AmberFlareSafeSink()).queryAmberFlare(dataHashMap);
    }
}

class CWE89_P11_V2_AmberFlareSafeSink {
    public void queryAmberFlare(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection amberFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberFlare");
        Statement amberFlareStatement = null;
        ResultSet amberFlareRows = null;
        try {
            amberFlareStatement = amberFlareConnection.createStatement();
            amberFlareRows = amberFlareStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberFlareRows.getRow());
        } finally {
            if (amberFlareRows != null) {
                amberFlareRows.close();
            }
            if (amberFlareStatement != null) {
                amberFlareStatement.close();
            }
            amberFlareConnection.close();
        }
    }
}
