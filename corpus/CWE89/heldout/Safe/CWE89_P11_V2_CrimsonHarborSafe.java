import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_CrimsonHarborSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void runCrimsonHarbor() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_CrimsonHarborSafeSink()).queryCrimsonHarbor(dataHashMap);
    }
}

class CWE89_P11_V2_CrimsonHarborSafeSink {
    public void queryCrimsonHarbor(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection crimsonHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonHarbor");
        Statement crimsonHarborStatement = null;
        ResultSet crimsonHarborRows = null;
        try {
            crimsonHarborStatement = crimsonHarborConnection.createStatement();
            crimsonHarborRows = crimsonHarborStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonHarborRows.getRow());
        } finally {
            if (crimsonHarborRows != null) {
                crimsonHarborRows.close();
            }
            if (crimsonHarborStatement != null) {
                crimsonHarborStatement.close();
            }
            crimsonHarborConnection.close();
        }
    }
}
