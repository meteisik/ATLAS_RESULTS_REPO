import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_ZephyrFlare {

    public void runZephyrFlare() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_FLARE_FILTER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_ZephyrFlareSink()).queryZephyrFlare(dataHashMap);
    }
}

class CWE89_P11_V1_ZephyrFlareSink {
    public void queryZephyrFlare(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection zephyrFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrFlare");
        Statement zephyrFlareStatement = null;
        ResultSet zephyrFlareRows = null;
        try {
            zephyrFlareStatement = zephyrFlareConnection.createStatement();
            zephyrFlareRows = zephyrFlareStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrFlareRows.getRow());
        } finally {
            if (zephyrFlareRows != null) {
                zephyrFlareRows.close();
            }
            if (zephyrFlareStatement != null) {
                zephyrFlareStatement.close();
            }
            zephyrFlareConnection.close();
        }
    }
}
