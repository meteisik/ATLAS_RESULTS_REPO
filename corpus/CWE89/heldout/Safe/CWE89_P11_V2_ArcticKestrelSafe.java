import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_ArcticKestrelSafe {

    public void runArcticKestrel() throws SQLException {
        String data;
        while (true) {
            data = "foo";
            break;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_ArcticKestrelSafeSink()).queryArcticKestrel(dataHashMap);
    }
}

class CWE89_P11_V2_ArcticKestrelSafeSink {
    public void queryArcticKestrel(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection arcticKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticKestrel");
        Statement arcticKestrelStatement = null;
        ResultSet arcticKestrelRows = null;
        try {
            arcticKestrelStatement = arcticKestrelConnection.createStatement();
            arcticKestrelRows = arcticKestrelStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticKestrelRows.getRow());
        } finally {
            if (arcticKestrelRows != null) {
                arcticKestrelRows.close();
            }
            if (arcticKestrelStatement != null) {
                arcticKestrelStatement.close();
            }
            arcticKestrelConnection.close();
        }
    }
}
