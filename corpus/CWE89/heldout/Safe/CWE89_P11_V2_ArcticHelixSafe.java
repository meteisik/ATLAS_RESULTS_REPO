import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_ArcticHelixSafe {

    public void runArcticHelix() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = "foo";
            break;
        default:
            data = null;
            break;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_ArcticHelixSafeSink()).queryArcticHelix(dataHashMap);
    }
}

class CWE89_P11_V2_ArcticHelixSafeSink {
    public void queryArcticHelix(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection arcticHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticHelix");
        Statement arcticHelixStatement = null;
        ResultSet arcticHelixRows = null;
        try {
            arcticHelixStatement = arcticHelixConnection.createStatement();
            arcticHelixRows = arcticHelixStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticHelixRows.getRow());
        } finally {
            if (arcticHelixRows != null) {
                arcticHelixRows.close();
            }
            if (arcticHelixStatement != null) {
                arcticHelixStatement.close();
            }
            arcticHelixConnection.close();
        }
    }
}
