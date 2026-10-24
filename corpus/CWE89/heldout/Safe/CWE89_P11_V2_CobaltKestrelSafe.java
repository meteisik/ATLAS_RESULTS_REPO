import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_CobaltKestrelSafe {

    public void runCobaltKestrel() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_CobaltKestrelSafeSink()).queryCobaltKestrel(dataHashMap);
    }
}

class CWE89_P11_V2_CobaltKestrelSafeSink {
    public void queryCobaltKestrel(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection cobaltKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltKestrel");
        Statement cobaltKestrelStatement = null;
        ResultSet cobaltKestrelRows = null;
        try {
            cobaltKestrelStatement = cobaltKestrelConnection.createStatement();
            cobaltKestrelRows = cobaltKestrelStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(cobaltKestrelRows.getRow());
        } finally {
            if (cobaltKestrelRows != null) {
                cobaltKestrelRows.close();
            }
            if (cobaltKestrelStatement != null) {
                cobaltKestrelStatement.close();
            }
            cobaltKestrelConnection.close();
        }
    }
}
