import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_SilentLotusSafe {

    public void runSilentLotus() throws SQLException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_SilentLotusSafeSink()).querySilentLotus(dataHashMap);
    }
}

class CWE89_P11_V1_SilentLotusSafeSink {
    public void querySilentLotus(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection silentLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentLotus");
        Statement silentLotusStatement = null;
        ResultSet silentLotusRows = null;
        try {
            silentLotusStatement = silentLotusConnection.createStatement();
            silentLotusRows = silentLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(silentLotusRows.getRow());
        } finally {
            if (silentLotusRows != null) {
                silentLotusRows.close();
            }
            if (silentLotusStatement != null) {
                silentLotusStatement.close();
            }
            silentLotusConnection.close();
        }
    }
}
