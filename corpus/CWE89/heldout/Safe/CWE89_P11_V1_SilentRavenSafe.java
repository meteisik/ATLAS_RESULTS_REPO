import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_SilentRavenSafe {

    public void runSilentRaven() throws SQLException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_SilentRavenSafeSink()).querySilentRaven(dataHashMap);
    }
}

class CWE89_P11_V1_SilentRavenSafeSink {
    public void querySilentRaven(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection silentRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentRaven");
        Statement silentRavenStatement = null;
        ResultSet silentRavenRows = null;
        try {
            silentRavenStatement = silentRavenConnection.createStatement();
            silentRavenRows = silentRavenStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(silentRavenRows.getRow());
        } finally {
            if (silentRavenRows != null) {
                silentRavenRows.close();
            }
            if (silentRavenStatement != null) {
                silentRavenStatement.close();
            }
            silentRavenConnection.close();
        }
    }
}
