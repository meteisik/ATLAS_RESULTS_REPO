import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_CrimsonBeaconSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runCrimsonBeacon() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_CrimsonBeaconSafeSink()).queryCrimsonBeacon(dataHashMap);
    }
}

class CWE89_P11_V2_CrimsonBeaconSafeSink {
    public void queryCrimsonBeacon(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection crimsonBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonBeacon");
        Statement crimsonBeaconStatement = null;
        ResultSet crimsonBeaconRows = null;
        try {
            crimsonBeaconStatement = crimsonBeaconConnection.createStatement();
            crimsonBeaconRows = crimsonBeaconStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonBeaconRows.getRow());
        } finally {
            if (crimsonBeaconRows != null) {
                crimsonBeaconRows.close();
            }
            if (crimsonBeaconStatement != null) {
                crimsonBeaconStatement.close();
            }
            crimsonBeaconConnection.close();
        }
    }
}
